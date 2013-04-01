#!/usr/bin/env python

import common
import sys, os, shutil
import magic

common.parse_args(sys.argv)

mime_type = magic.from_file(common.file_path, True)
if not os.path.isdir(common.file_path):
    if mime_type == 'text/x-php':
        os.remove(common.file_path)
