/*
 * inotify-sync - a simple file synchronizer and file system watcher
 * Copyright (C) 2010-2013, inotify-sync developers and inotify-sync contributors
 * Copyright (C) 2010-2013, Cohesion Network Security Studio
 *
 * inotify-sync is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * inotify-sync is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with inotify-sync; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "event_watcher.h"

ievent_queue_t *ievent_queue_head = NULL;

pthread_rwlock_t ievent_p_vec_lock;
pthread_rwlock_t dnode_vec_lock;

char **wd_path_map = NULL;
int wd_path_max = 0; 
int wd_path_count = 0;

int fd;
uint32_t mask;

pthread_t event_watcher_tid;

void event_watcher_init();
void event_watcher_destory();
void event_watcher_start();
void event_watcher_wait();
void event_watcher_init_dir(const char *root_dir);
void event_watcher_destory_dir(const char *root_dir);
int do_init_dir(const char *fpath,
		const struct stat *sb,
		int typeflag);
void * event_watcher_main_loop(void *args);
void * handle_events(void *args);

void
event_watcher_init()
{
	int i, errnum = 0;

	if((fd = inotify_init()) == -1) {
		err_exit("init inotify error");
	}

	mask = 0;
	for(i = 0; i < NACTIONS; i++)
	{
		if(actions[i].filename == NULL) {
			continue;
		}
		if(0 != strcmp(actions[i].filename, "")) {
			mask |= actions[i].event;
		}
	}

	if((errnum = pthread_rwlock_init(&ievent_p_vec_lock,NULL)) != 0)
	{
		user_exit1("init pthread lock error: %s", strerror(errnum));
	}
	if((errnum = pthread_rwlock_init(&dnode_vec_lock,NULL)) != 0)
	{
		user_exit1("init pthread lock error: %s", strerror(errnum));
	}

	// 为wd_path_map数组分配初始空间
	wd_path_max = 100;
	wd_path_count = 0;
	wd_path_map = (char **)malloc(sizeof(char *) * wd_path_max);

	event_watcher_init_dir(watch_dir);
}

void
event_watcher_destory()
{
	int errnum;

	if((errnum = pthread_rwlock_destroy(&ievent_p_vec_lock)) != 0)
	{
		user_exit1("destory pthread lock error: %s", strerror(errnum));
	}
	if((errnum = pthread_rwlock_destroy(&dnode_vec_lock)) != 0)
	{
		user_exit1("destory pthread lock error: %s", strerror(errnum));
	}

	if(-1 == close(fd))
	{
		err_exit("close inotify error");
	}
}

void
event_watcher_init_dir(const char *root_dir)
{
	int errnum;

	// 如果没有rx权限访问watch_dir，报错退出
	if(-1 == access(root_dir, R_OK|X_OK))
	{
		err_exit1("access watch_dir error: %s", root_dir);
	}
	if((errnum = pthread_rwlock_wrlock(&dnode_vec_lock)) != 0)
	{
		user_exit1("lock pthread lock error: %s", strerror(errnum));
	}
	
	ftw(root_dir, do_init_dir, 500);

	if((errnum = pthread_rwlock_unlock(&dnode_vec_lock)) != 0)
	{
		user_exit1("unlock pthread lock error: %s", strerror(errnum));
	}
}

int
do_init_dir(const char *fpath,
		const struct stat *sb,
		int typeflag)
{
	int wd, fpath_len;
	char fpath1[PATH_MAX], *filename;

	// do not monitor the file, only monitor directory
	if(typeflag == FTW_F) {
		return 0;
	}
	// if watch_hidden in conf is NO, do not watch hidden directory
	strcpy(fpath1, fpath);
	filename = basename(fpath1);
	if(!strcmp(watch_hidden, "NO") && *filename == '.') {
		return 0;
	}
	// add watch
	if((wd = inotify_add_watch(fd, fpath, mask)) == -1) {
		err_exit("add inotify watcher error");
	}
	if(wd_path_count == wd_path_max) {
		wd_path_max += 100;
		wd_path_map = (char **)realloc(wd_path_map, sizeof(char *) * wd_path_max);
	}
	fpath_len = strlen(fpath);
	wd_path_map[wd] = (char *)malloc(fpath_len + 1);
	strncpy(wd_path_map[wd], fpath, fpath_len + 1);
	wd_path_count++;

	return 0;
}

void
event_watcher_destory_dir(const char *root_dir)
{
	int i;
	int errnum;

	if((errnum = pthread_rwlock_wrlock(&dnode_vec_lock)) != 0) {
		user_exit1("lock pthread lock error: %s", strerror(errnum));
	}

	for(i = 1; i <= wd_path_count; i++) {
		if(!strcmp(root_dir, wd_path_map[i])) {
			free(wd_path_map[i]);
			break;
		}
	}

	if((errnum = pthread_rwlock_unlock(&dnode_vec_lock)) != 0) {
		user_exit1("unlock pthread lock error: %s", strerror(errnum));
	}
}

void
event_watcher_start()
{
	int errnum;

	//Create thread to run event_watcher_main_loop
	if((errnum = pthread_create(&event_watcher_tid, NULL,
		event_watcher_main_loop, NULL)) != 0)
	{
		user_exit1("create new thread error: %s", strerror(errnum));
	}
}

void
event_watcher_wait()
{
	int errnum;
	void *ret;

	//Join thread from event_watcher_main_loop
	if((errnum = pthread_join(event_watcher_tid, &ret)) != 0)
	{
		user_exit1("join thread error: %s", strerror(errnum));
	}
}

void *
event_watcher_main_loop(void *args)
{
	int length = 0;
	char buf[sizeof(struct inotify_event) + NAME_MAX + 1] = {0};

	while((length = read(fd, buf, sizeof(buf))) != -1)
	{
		int buf_offset = 0;
		int errnum;
		struct inotify_event *p_event = NULL, *event = NULL;
		ievent_queue_t *cur, *n;

		while(buf_offset < length)
		{
			size_t event_size;
			p_event=(struct inotify_event *)&buf[buf_offset];
			event_size=offsetof(struct inotify_event,name)
							+p_event->len;
			event=(struct inotify_event *)malloc(event_size);
			memcpy(event,p_event,event_size);

			//Lock ievent_p_vec and push_back event to it
			if((errnum = pthread_rwlock_wrlock(&ievent_p_vec_lock)) != 0)
			{
				user_exit1("lock pthread lock error: %s", strerror(errnum));
			}
			n = (ievent_queue_t *)malloc(sizeof(ievent_queue_t));
			n->event = event;
			n->next = NULL;
			if(ievent_queue_head == NULL)
			{
				ievent_queue_head = n;
			}
			else
			{
				cur = ievent_queue_head;
				while(cur->next != NULL) {
					cur = cur->next;
				}
				cur->next = n;
			}
			if((errnum = pthread_rwlock_unlock(&ievent_p_vec_lock)) != 0)
			{
				user_exit1("unlock pthread lock error: %s", strerror(errnum));
			}

			buf_offset += event_size;
		}
	}
	return ((void *)0);
}
