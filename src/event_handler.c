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

#include "event_handler.h"

void event_handler_init();
void event_handler_destory();
void event_handler_start();
void *event_handler_main_loop(void *args);
void event_handler_handle_event();
void exec_action(action_t *action, const char *path, const char *cookie);
pthread_t event_handler_tid;

void
event_handler_init()
{
	int i;
	char path[PATH_MAX];

	if(-1 == access(watch_dir, R_OK|X_OK))
	{
		err_exit1("watch directory '%s'", watch_dir);
	}

	// 同步目录如果不为空则必须有rwx的权限
	if(strcmp(sync_dir, "") && -1 == access(sync_dir, R_OK|W_OK|X_OK))
	{
		err_exit1("sync directory '%s'", watch_dir);
	}

	for(i = 0; i < NACTIONS; i++)
	{
		if(actions[i].filename == NULL) {
			continue;
		}
		snprintf(path, sizeof(path), "%s/%s", action_dir,
			actions[i].filename);
		if(strcmp(actions[i].filename, "")
		&& -1 == access(path, R_OK|X_OK))
		{
			err_exit1("action file '%s'", path);
		}
	}

	if(-1 == access(TEMP_DIR, F_OK)) {
		if(-1 == mkdir(TEMP_DIR, 0700)) {
			err_exit1("create temp directory '%s' error",
				TEMP_DIR);
		}
	}
	
	if(!strcmp(log_enable, "YES")) {
		log_init();
	}
}

void
event_handler_destory()
{}

void
event_handler_start()
{
	int errnum;

	//Create thread to run event_handler_main_loop
	if((errnum = pthread_create(&event_handler_tid, NULL,
		event_handler_main_loop, NULL)) != 0)
	{
		user_exit1("create new thread error: %s", strerror(errnum));
	}
}

void
event_handler_wait()
{
	int errnum;
	void *ret;

	//Join thread from event_handler_main_loop
	if((errnum = pthread_join(event_handler_tid, &ret)) != 0)
	{
		user_exit1("join thread error: %s", strerror(errnum));
	}
}

void *
event_handler_main_loop(void *args)
{
	int errnum;
	while((errnum = pthread_rwlock_wrlock(&ievent_p_vec_lock)) == 0)
	{
		if(ievent_queue_head != NULL)
		{
			ievent_queue_t *i = ievent_queue_head, *tmp;
			event_handler_handle_event();
			while(i != NULL)
			{
				tmp = i->next;
				free(i->event);
				free(i);
				i = tmp;
			}
			ievent_queue_head = NULL;
		}
		if((errnum = pthread_rwlock_unlock(&ievent_p_vec_lock)) != 0)
		{
			user_exit1("unlock pthread lock error: %s", strerror(errnum));
		}
	}
	if(errnum != 0)
	{
		user_exit1("lock pthread lock error: %s", strerror(errnum));
	}
	return ((void *)0);
}

void
event_handler_handle_event()
{
	ievent_queue_t *iq_node_p = ievent_queue_head;

	while(iq_node_p != NULL)
	{
		// 事件指针
		struct inotify_event *p_ievent = NULL;
		// absolute path and relative path
		char path[PATH_MAX];
		// 事件掩码
		uint32_t mask;
		// 事件cookie
		char cookie[12];
		int i;

		// 取出当前事件指针
		p_ievent = iq_node_p->event;
		// 根据当前事件wd获得事件发生目录
		strcpy(path, wd_path_map[p_ievent->wd]);
		// 事件掩码
		mask = p_ievent->mask;
		// 获得事件cookie
		sprintf(cookie, "%d", p_ievent->cookie);

		// 如不为IN_DELETE_SELF或IN_MOVE_SELF事件
		// 则绝对路径为：事件发生目录 + 文件名
		if(!(mask & IN_DELETE_SELF)
		&& !(mask & IN_MOVE_SELF)) {
			strcat(path, "/");
			strncat(path, p_ievent->name, p_ievent->len);
		}

		// 对创建目录事件，初始化监控目录
		if((mask & IN_CREATE) && (mask & IN_ISDIR))
		{
			event_watcher_init_dir(path);
		}
		// 对删除目录事件，撤销监控目录
		if((mask & IN_DELETE) && (mask & IN_ISDIR))
		{
			event_watcher_destory_dir(path);
		}
		// 对移入目录事件，初始化监控目录
		if((mask & IN_MOVED_TO) && (mask & IN_ISDIR))
		{
			event_watcher_init_dir(path);
		}
		// 对移出目录事件，初始化监控目录
		if((mask & IN_MOVED_FROM) && (mask & IN_ISDIR))
		{
			event_watcher_destory_dir(path);
		}

		for(i = 0; i < NACTIONS; i++)
		{
			if(!(mask & actions[i].event)) {
				continue;
			}
			if(!strcmp(log_enable, "YES")) {
				log_event(&actions[i], path, p_ievent->cookie);
			}
			exec_action(&actions[i], path, cookie);
		}
		iq_node_p = iq_node_p->next; 
	}
}

void
exec_action(action_t *action, const char *path, const char *cookie)
{
	pid_t pid;
	char action_path[PATH_MAX];

	snprintf(action_path, sizeof(action_path), "%s/%s",
		action_dir, action->filename);

	if((pid = fork()) < 0) {
		perror("fork a new process to execute action error");
	} else if(pid == 0) {
		execl(action_path, action->filename, watch_dir, sync_dir,
			TEMP_DIR, path, cookie, (char *)0);
	}

	if(waitpid(pid, NULL, 0) < 0) {
		err_exit1("wait process %d error", pid);
	}
}
