#!/usr/bin/env python

"""
Process cgroups
"""

import sys

import lib_uris
import lib_util
import lib_common
from sources_types import CIM_Process
from lib_properties import pc
from sources_types.Linux import cgroup as survol_cgroup

# $ cat /proc/22948/cgroup
# 11:devices:/user.slice
# 10:memory:/
# 9:cpuset:/


def Main():
    cgiEnv = lib_common.ScriptEnvironment()
    try:
        the_pid = int(cgiEnv.GetId())
    except Exception:
        lib_common.ErrorMessageHtml("Must provide a pid")

    grph = cgiEnv.GetGraph()

    node_process = lib_uris.gUriGen.PidUri(the_pid)
    CIM_Process.AddInfo(grph, node_process, [str(the_pid)])

    fil_cgroups = "/proc/%d/cgroup" % the_pid

    for lin_cg in open(fil_cgroups):
        split_cg = lin_cg.split(':')
        hierarchy = split_cg[0]
        subsys_name_list = split_cg[1]
        mount_path = split_cg[2]
        mount_path = mount_path[:-1] # Strip trailing backslash-N
        mount_path_node = lib_uris.gUriGen.DirectoryUri(mount_path)

        for subsys_name in subsys_name_list.split(","):
            if subsys_name:
                cgrp_node = survol_cgroup.MakeUri(subsys_name)
                grph.add((node_process, lib_common.MakeProp("CGroup"), cgrp_node))
                grph.add((cgrp_node, lib_common.MakeProp("Hierarchy"), lib_util.NodeLiteral(hierarchy)))
                grph.add((cgrp_node, lib_common.MakeProp("Control group path"), mount_path_node))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
