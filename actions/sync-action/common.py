#!/usr/bin/env python

import os

watch_dir = ''
sync_dir = ''
temp_dir = ''
file_path = ''
cookie = 0
sync_path = ''
temp_path = ''

def parse_args(args):
    global watch_dir, sync_dir, temp_dir, file_path, sync_path, cookie, temp_path
    watch_dir = args[1]
    sync_dir = args[2]
    temp_dir = args[3]
    file_path = args[4]
    cookie = args[5]
    sync_path = file_path.replace(watch_dir, sync_dir, 1);
    temp_path = os.path.join(temp_dir, cookie)
