#!/usr/bin/env python

"""
Remote machine Windows services
"""

import sys
import lib_util
import lib_common
from lib_properties import pc
from sources_types import Win32_Service


def Main():
    cgiEnv = lib_common.ScriptEnvironment()
    machine_name = cgiEnv.GetId()

    grph = cgiEnv.GetGraph()

    try:
        Win32_Service.FullServiceNetwork(grph, machine_name)
    except Exception as exc:
        lib_common.ErrorMessageHtml("win32 " + machine_name + " services:" + str(exc))

    cgiEnv.OutCgiRdf("LAYOUT_SPLINE")


if __name__ == '__main__':
    Main()

  
