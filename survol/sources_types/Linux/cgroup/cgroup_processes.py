#!/usr/bin/python

"""
Processes in a cgroup
"""

import sys
import re
import socket
import socket
import lib_util
import lib_common
from lib_properties import pc
from sources_types import CIM_Process
from sources_types.Linux import cgroup as survol_cgroup

def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	cgroupName = cgiEnv.GetId()
	cgroupNode = survol_cgroup.MakeUri(cgroupName)

	propCGroup = lib_common.MakeProp("cgroup")

	# This file contains all processes belonging to this cgroup.
	# Example "/sys/fs/cgroup/cpuset/cgroup.procs"
	# Read access might be forbidden.
	filNamCGroup = "/sys/fs/cgroup/%s/cgroup.procs" % cgroupName

	for lin_cg in open(filNamCGroup):
		procId = int(lin_cg)
		procNode = lib_common.gUriGen.PidUri(procId)

		grph.add( ( cgrpNode, propCGroup, procNode ) )

	# This lists processes in a table instead of scattered nodes.
	# This is because there might be a lot of processes.
	cgiEnv.OutCgiRdf("LAYOUT_RECT", [propCGroup] )

if __name__ == '__main__':
	Main()
