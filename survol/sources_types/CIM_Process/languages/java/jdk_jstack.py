#!/usr/bin/env python

"""
Full thread dump Java HotSpot (TM)
"""

import sys
import lib_common
from sources_types import CIM_Process
from sources_types import java as survol_java
from lib_properties import pc

# Not implemented yet.

def Main():
    cgiEnv = lib_common.CgiEnv()
    pidInt = int( cgiEnv.GetId() )

    grph = cgiEnv.GetGraph()

    node_process = lib_common.gUriGen.PidUri(pidInt)
    proc_obj = CIM_Process.PsutilGetProcObj(pidInt)

    cgiEnv.OutCgiRdf()

if __name__ == '__main__':
    Main()
