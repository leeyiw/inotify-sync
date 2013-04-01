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

#include "utils.h"

inline void
user_exit(const char *str)
{
	fprintf(stderr, "%s\n", str);
	exit(EXIT_FAILURE);
}

inline void
user_exit1(const char *format, ...)
{
	va_list ap;
	char buf[1024];

	va_start(ap, format);
	vsprintf(buf, format, ap);
	fprintf(stderr, "%s\n", buf);
	va_end(ap);
	exit(EXIT_FAILURE);
}

inline void
err_exit(const char *str)
{
	perror(str);
	exit(EXIT_FAILURE);
}

inline void
err_exit1(const char *format, ...)
{
	va_list ap;
	char buf[1024];

	va_start(ap, format);
	vsprintf(buf, format, ap);
	fprintf(stderr, "%s: %s\n", buf, strerror(errno));
	va_end(ap);
	exit(EXIT_FAILURE);
}
