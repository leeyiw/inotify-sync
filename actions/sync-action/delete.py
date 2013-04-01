#!/usr/bin/env python

import common
import sys, os, shutil

common.parse_args(sys.argv)

if common.sync_dir != '':
    if os.path.isdir(common.file_path):
        shutil.rmtree(common.sync_path);
    else:
        os.remove(common.sync_path)
