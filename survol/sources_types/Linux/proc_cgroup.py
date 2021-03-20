#!/usr/bin/env python

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
    cgiEnv = lib_common.ScriptEnvironment()

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

        cgrp_node = survol_cgroup.MakeUri(subsys_name)
        grph.add((cgrp_node, lib_common.MakeProp("Hierarchy"), lib_util.NodeLiteral(hierarchy)))
        grph.add((cgrp_node, lib_common.MakeProp("Num CGroups"), lib_util.NodeLiteral(num_cgroups)))
        grph.add((cgrp_node, lib_common.MakeProp("Enabled"), lib_util.NodeLiteral(enabled)))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
