#!/usr/bin/env python

"""
Process cgroups
"""

import sys
import lib_common
from sources_types import CIM_Process
from lib_properties import pc

from sources_types.Linux import cgroup as survol_cgroup

# $ cat /proc/22948/cgroup
# 11:devices:/user.slice
# 10:memory:/
# 9:cpuset:/


def Main():
    cgiEnv = lib_common.CgiEnv()
    try:
        thePid = int( cgiEnv.GetId() )
    except Exception:
        lib_common.ErrorMessageHtml("Must provide a pid")

    grph = cgiEnv.GetGraph()

    proc_obj = CIM_Process.PsutilGetProcObj(thePid)

    node_process = lib_common.gUriGen.PidUri(thePid)
    CIM_Process.AddInfo( grph, node_process, [ str(thePid) ] )

    filCGroups = "/proc/%d/cgroup" % thePid

    for lin_cg in open(filCGroups):
        split_cg = lin_cg.split(':')
        hierarchy = split_cg[0]
        subsys_name_list = split_cg[1]
        mount_path = split_cg[2]
        mount_path = mount_path[:-1] # Strip trailing backslash-N
        mount_path_node = lib_common.gUriGen.DirectoryUri( mount_path )

        for subsys_name in subsys_name_list.split(","):
            if subsys_name:
                cgrpNode = survol_cgroup.MakeUri( subsys_name )
                grph.add( ( node_process, lib_common.MakeProp("CGroup"), cgrpNode ) )
                grph.add( ( cgrpNode, lib_common.MakeProp("Hierarchy"), lib_common.NodeLiteral(hierarchy) ) )
                grph.add( ( cgrpNode, lib_common.MakeProp("Control group path"), mount_path_node ) )

    cgiEnv.OutCgiRdf()

if __name__ == '__main__':
    Main()
