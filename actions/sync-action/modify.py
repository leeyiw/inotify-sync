#!/usr/bin/env python

import common
import sys, os, shutil

common.parse_args(sys.argv)

if common.sync_dir != '':
    if os.path.isdir(common.file_path):
        shutil.copytree(common.file_path, common.sync_path);
    else:
        shutil.copyfile(common.file_path, common.sync_path);
