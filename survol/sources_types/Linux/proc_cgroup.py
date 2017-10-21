#!/usr/bin/python

"""
CGroups on a Linux platform
"""

# #subsys_name    hierarchy       num_cgroups     enabled
# cpuset  9       1       1
# cpu     6       1       1
# cpuacct 6       1       1


import sys
import lib_util
import lib_common
from lib_properties import pc

from sources_types.Linux import cgroup as survol_cgroup

def Main():
	cgiEnv = lib_common.CgiEnv()

	if not lib_util.isPlatformLinux:
		lib_common.ErrorMessageHtml("/etc/group for Linux only")

	grph = cgiEnv.GetGraph()

	for lin_cg in open("/proc/cgroups"):
		# Just in case there would be a comment.
		lin_cg = lin_cg.strip()
		if lin_cg.startswith("#"):
			continue
		split_cg = lin_cg.split('\t')
		subsys_name = split_cg[0]
		hierarchy = split_cg[1]
		num_cgroups = split_cg[2]
		enabled = split_cg[3]

		cgrpNode = survol_cgroup.MakeUri( subsys_name )
		grph.add( ( cgrpNode, lib_common.MakeProp("Hierarchy"), lib_common.NodeLiteral(hierarchy) ) )
		grph.add( ( cgrpNode, lib_common.MakeProp("Num CGroups"), lib_common.NodeLiteral(num_cgroups) ) )
		grph.add( ( cgrpNode, lib_common.MakeProp("Enabled"), lib_common.NodeLiteral(enabled) ) )

	cgiEnv.OutCgiRdf()


if __name__ == '__main__':
	Main()
