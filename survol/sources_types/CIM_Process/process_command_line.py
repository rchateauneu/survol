#!/usr/bin/env python

"""
Command line
"""

import os
import sys

import lib_uris
import lib_util
import lib_common
from lib_properties import pc
from sources_types import CIM_Process


def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    grph = cgiEnv.GetGraph()

    try:
        procid = int(cgiEnv.GetId())
    except Exception:
        lib_common.ErrorMessageHtml("Must provide a pid")

    obj_proc = CIM_Process.PsutilGetProcObj(procid)

    node_process = lib_uris.gUriGen.PidUri(procid)

    CIM_Process.add_command_line_arguments(grph, node_process, obj_proc)

    cgiEnv.OutCgiRdf("LAYOUT_RECT")


if __name__ == '__main__':
    Main()

