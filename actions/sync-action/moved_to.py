#!/usr/bin/env python

import common
import sys, os, shutil

common.parse_args(sys.argv)

if common.sync_dir != '' and common.temp_dir != '':
    if os.path.exists(common.temp_path):
        shutil.move(common.temp_path, common.sync_path);
    else:
        if os.path.isdir(common.file_path):
            shutil.copytree(common.file_path, common.sync_path);
        else:
            shutil.copyfile(common.file_path, common.sync_path);
