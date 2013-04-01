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

#include "config.h"

cfg_t *cfg, *cfg_action;

const char *watch_dir;
const char *sync_dir;
const char *watch_hidden;
const char *log_enable;
const char *log_path;

const char *action_dir;
action_t actions[12] = {
	{IN_ACCESS, "access_action", NULL, "ACCESS"}, 
	{IN_ATTRIB, "attrib_action", NULL, "ATTRIB"}, 
	{IN_CLOSE_WRITE, "close_write_action", NULL, "CLOSE_WRITE"}, 
	{IN_CLOSE_NOWRITE, "close_nowrite_action", NULL, "CLOSE_NOWRITE"}, 
	{IN_CREATE, "create_action", NULL, "CREATE"}, 
	{IN_DELETE, "delete_action", NULL, "DELETE"}, 
	{IN_DELETE_SELF, "delete_self_action", NULL, "DELETE_SELF"}, 
	{IN_MODIFY, "modify_action", NULL, "MODIFY"}, 
	{IN_MOVE_SELF, "move_self_action", NULL, "MOVE_SELF"}, 
	{IN_MOVED_FROM, "moved_from_action", NULL, "MOVED_FROM"}, 
	{IN_MOVED_TO, "moved_to_action", NULL, "MOVED_TO"}, 
	{IN_OPEN, "open_action", NULL, "OPEN"}
};

static cfg_opt_t action_opts[] = {
	CFG_STR("action_dir", "", CFGF_NONE),
	CFG_STR("access_action", "", CFGF_NONE),
	CFG_STR("attrib_action", "", CFGF_NONE),
	CFG_STR("close_write_action", "", CFGF_NONE),
	CFG_STR("close_nowrite_action", "", CFGF_NONE),
	CFG_STR("create_action", "", CFGF_NONE),
	CFG_STR("delete_action", "", CFGF_NONE),
	CFG_STR("delete_self_action", "", CFGF_NONE),
	CFG_STR("modify_action", "", CFGF_NONE),
	CFG_STR("move_self_action", "", CFGF_NONE),
	CFG_STR("moved_from_action", "", CFGF_NONE),
	CFG_STR("moved_to_action", "", CFGF_NONE),
	CFG_STR("open_action", "", CFGF_NONE),
	CFG_END()
};

static cfg_opt_t opts[] = {
	CFG_STR("watch_dir", NULL, CFGF_NONE),
	CFG_STR("sync_dir", "", CFGF_NONE),
	CFG_STR("watch_hidden", "NO", CFGF_NONE),
	CFG_STR("log_enable", "YES", CFGF_NONE),
	CFG_STR("log_path", "", CFGF_NONE),
	CFG_SEC("action", action_opts, CFGF_NONE),
	CFG_END()
};

void
config_init()
{
	int i;

	cfg = cfg_init(opts, CFGF_NONE);
	if(cfg_parse(cfg, CONF_PATH) == CFG_PARSE_ERROR) {
		user_exit("parse config file error");
	}
	cfg_action = cfg_getsec(cfg, "action");

	watch_dir = cfg_getstr(cfg, "watch_dir");
	sync_dir = cfg_getstr(cfg, "sync_dir");
	watch_hidden = cfg_getstr(cfg, "watch_hidden");
	log_enable = cfg_getstr(cfg, "log_enable");
	log_path = cfg_getstr(cfg, "log_path");

	action_dir = cfg_getstr(cfg_action, "action_dir");
	for(i = 0; i < NACTIONS; i++) {
		actions[i].filename = cfg_getstr(cfg_action, actions[i].name);
	}
}
