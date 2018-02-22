#!/usr/bin/python

"""
List of Linux cgroups
"""

import lib_util
import lib_common

# cat /proc/cgroups
# #subsys_name    hierarchy       num_cgroups     enabled
# cpuset  0       1       1
# cpu     0       1       1
# cpuacct 0       1       1
# blkio   0       1       1
# memory  0       1       1
# devices 0       1       1
# freezer 0       1       1
# net_cls 0       1       1
# perf_event      0       1       1
# net_prio        0       1       1
# pids    0       1       1


Usable = lib_util.UsableLinux

def Main():
	cgiEnv = lib_common.CgiEnv()

	lib_common.ErrorMessageHtml("Not implemented yet")

