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

/*
 * FILE:		event_handler.h
 * USAGE:		---
 * DESCRIPTION:		---
 * OPTIONS:		---
 * REQUIREMENTS:	---
 * BUGS:		---
 * NOTES:		---
 * AUTHOR:		LI Yiwei (mail:leeyiw@gmail.com)
 * COMPANY:		---
 * VERSION:		1.0
 * CREATED:		Wed Oct  5 13:09:12 CST 2011
 * REVISION:		---
 */


#ifndef _EVENT_HANDLER_H
#define _EVENT_HANDLER_H

#include <sys/types.h>
#include <sys/wait.h>
#include <limits.h>

#include "event_watcher.h"
#include "config.h"
#include "log.h"

#define ISDIR(mask) ((mask & IN_ISDIR)?"YES":"NO")

extern void event_handler_init();
extern void event_handler_destory();
extern void event_handler_start();
extern void event_handler_wait();

#endif
