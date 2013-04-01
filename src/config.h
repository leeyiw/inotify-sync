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

#ifndef _CONFIG_H
#define _CONFIG_H

#include <confuse.h>
#include <sys/inotify.h>

#include "defines.h"
#include "utils.h"

#ifndef CONF_PATH
#define CONF_PATH	"/usr/local/etc/inotify-sync.conf"
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define TEMP_DIR	"/tmp/inotify-sync"
#define NACTIONS	(sizeof(actions)/sizeof(actions[0]))

typedef struct _action_t {
	uint32_t event;
	const char *name;
	const char *filename;
	const char *log_name;
} action_t;

extern const char *watch_dir;
extern const char *sync_dir;
extern const char *watch_hidden;
extern const char *log_enable;
extern const char *log_path;

extern const char *action_dir;
extern action_t actions[12];

extern void config_init();

#endif
