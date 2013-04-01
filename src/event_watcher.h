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

#ifndef _EVENT_WATCHER_H
#define _EVENT_WATCHER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include <time.h>
#include <sys/inotify.h>
#include <signal.h>
#include <setjmp.h>
#include <errno.h>
#include <pthread.h>
#include <ftw.h>
#include <libgen.h>

#include "config.h"

typedef struct _ievent_queue_t
{
	struct inotify_event *event;
	struct _ievent_queue_t *next;
} ievent_queue_t;

#include "event_handler.h"

extern void event_watcher_init();
extern void event_watcher_destory();
extern void event_watcher_start();
extern void event_watcher_wait();
extern void event_watcher_init_dir(const char *root_dir);
extern void event_watcher_destory_dir(const char *root_dir);

extern ievent_queue_t *ievent_queue_head;
extern pthread_rwlock_t ievent_p_vec_lock;
extern pthread_rwlock_t dnode_vec_lock;

extern char **wd_path_map;
extern int wd_path_max; 
extern int wd_path_count;

#endif
