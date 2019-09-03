#!/usr/bin/env python

import os
import re
import time
import pwd

group_name = ""
user_name = ""

dict_processes = {}
while True:
    new_dict = {}
    for root, dirs, files in os.walk("/proc"):
        for proc_dir in dirs:
            if re.match("[0-9]*", proc_dir):
                try:
                    new_dict[proc_dir] = dict_processes.pop(proc_dir)
                except KeyError:
                    try:
                        cmdline_file = open("/proc/%s/cmdline" % proc_dir)
                        cmdline = "".join(cmdline_file.readlines())
                        cmdline_file.close()
                    except Exception as exc:
                        cmdline = exc
                    new_dict[proc_dir] = {"cmdline":cmdline, "uid": "??"}
                    # Print new process
        break
    for exit_process in dict_processes:
        print("Exit:",exit_process)
    dict_processes = new_dict

    time.sleep(10.0)
