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

#include "log.h"

static FILE *log_fp;

void
log_init()
{
	log_fp = fopen(log_path, "w+");
	if(log_fp == NULL) {
		err_exit1("open log file '%s' error", log_path);
	}
	tzset();
}

void
log_event(action_t *action, const char *file, uint32_t cookie)
{
	time_t t;
	struct tm ctm, *ret;
	char action_path[PATH_MAX];


	t = time(NULL);
	ret = localtime_r(&t, &ctm);
	if(ret == NULL) {
		err_exit("log module get time error");
	}
	// log time
	fprintf(log_fp, "[%02d/%02d/%d:%02d:%02d:%02d %s]", ctm.tm_mday,
		ctm.tm_mon + 1,	ctm.tm_year + 1900, ctm.tm_hour, ctm.tm_min,
		ctm.tm_sec, tzname[0]);
	// log file path
	fprintf(log_fp, " \"%s\"", file);
	// log what kind of event
	fprintf(log_fp, " %s", action->log_name);
	fprintf(log_fp, " %d", cookie);
	// log action file path
	snprintf(action_path, sizeof(action_path), "%s/%s",
		action_dir, action->filename);
	fprintf(log_fp, " \"%s\"", action_path);
	fprintf(log_fp, "\n");
	fflush(log_fp);
}
