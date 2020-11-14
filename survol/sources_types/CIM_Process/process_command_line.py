#!/usr/bin/env python

"""
Command line
"""

import os
import sys
import lib_util
import lib_common
from lib_properties import pc
from sources_types import CIM_Process


def Main():
    cgiEnv = lib_common.CgiEnv()

    grph = cgiEnv.GetGraph()

    try:
        procid = int(cgiEnv.GetId())
    except Exception:
        lib_common.ErrorMessageHtml("Must provide a pid")

    obj_proc = CIM_Process.PsutilGetProcObj(procid)

    try:
        # Psutil version after 4.0.0
        envs_dict = obj_proc.environ()
    except Exception as exc:
        lib_common.ErrorMessageHtml("Error:" + str(exc))

    node_process = lib_common.gUriGen.PidUri(procid)

    CIM_Process.add_command_line_arguments(grph, node_process, obj_proc)

    # cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_argv])
    cgiEnv.OutCgiRdf("LAYOUT_RECT")


if __name__ == '__main__':
    Main()

