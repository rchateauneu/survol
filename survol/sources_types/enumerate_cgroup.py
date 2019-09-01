#!/usr/bin/env python

"""
List of Linux cgroups
"""

import lib_util
import lib_common

from sources_types.Linux import cgroup as survol_cgroup

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
    grph = cgiEnv.GetGraph()

    filCG = open("/proc/cgroups")
    propCGroup = lib_common.MakeProp("cgroup")

    linHeader = filCG.readline()
    for linCG in filCG.readlines():
        splitCG = linCG.split("\t")
        cgroupName = splitCG[0]
        cgroupNode = survol_cgroup.MakeUri(cgroupName)
        grph.add( ( cgroupNode, lib_common.MakeProp("Hierarchy"), lib_common.NodeLiteral(splitCG[1] ) ) )
        grph.add( ( cgroupNode, lib_common.MakeProp("Num cgroups"), lib_common.NodeLiteral(splitCG[2] ) ) )
        grph.add( ( cgroupNode, lib_common.MakeProp("Enabled"), lib_common.NodeLiteral(splitCG[3] ) ) )

        grph.add( ( lib_common.nodeMachine, propCGroup, cgroupNode ) )

        
    cgiEnv.OutCgiRdf("LAYOUT_RECT", [propCGroup] )

if __name__ == '__main__':
    Main()

