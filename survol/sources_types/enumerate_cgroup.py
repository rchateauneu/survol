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

    fil_cg = open("/proc/cgroups")
    prop_cgroup = lib_common.MakeProp("cgroup")

    linHeader = fil_cg.readline()
    for lin_cg in fil_cg.readlines():
        split_cg = lin_cg.split("\t")
        cgroup_name = split_cg[0]
        cgroup_node = survol_cgroup.MakeUri(cgroup_name)
        grph.add((cgroup_node, lib_common.MakeProp("Hierarchy"), lib_util.NodeLiteral(split_cg[1])))
        grph.add((cgroup_node, lib_common.MakeProp("Num cgroups"), lib_util.NodeLiteral(split_cg[2])))
        grph.add((cgroup_node, lib_common.MakeProp("Enabled"), lib_util.NodeLiteral(split_cg[3])))

        grph.add((lib_common.nodeMachine, prop_cgroup, cgroup_node))

    cgiEnv.OutCgiRdf("LAYOUT_RECT", [prop_cgroup])


if __name__ == '__main__':
    Main()

