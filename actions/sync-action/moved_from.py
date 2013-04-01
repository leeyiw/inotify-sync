#!/usr/bin/env python

import common
import sys, os, shutil

common.parse_args(sys.argv)

if common.sync_dir != '' and common.temp_dir != '':
    shutil.move(common.sync_path, common.temp_path);
