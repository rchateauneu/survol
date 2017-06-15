#!/usr/bin/python

"""
Python stack
"""

import os
import re
import sys
import rdflib
import lib_util
import lib_common
from lib_properties import pc
from sources_types import symbol as survol_symbol
from sources_types import CIM_Process
from sources_types.CIM_Process.languages import python as survol_python

Usable = survol_python.Usable

def Usable(entity_type,entity_ids_arr):
    """Python and Linux processes"""
    isLinux = lib_util.UsableLinux(entity_type,entity_ids_arr)
    if not isLinux:
        return False

    # This tells if it is a Python process.
    return CIM_Process.Usable(entity_type,entity_ids_arr)


def GetRemoteStack(thePid):
    # These Python instructions will be executed by a debugger in the context of a Python process.
    # The result is a vector of strings, the output of the execution.
    vecInstructions = [
        'import json',
        'import traceback',
        'retobj = traceback.extract_stack()'
    ]
    objResu = survol_python.ExecInPythonDebugger(thePid,vecInstructions)
    return objResu

def Main():
    cgiEnv = lib_common.CgiEnv()
    pid = int( cgiEnv.GetId() )

    grph = cgiEnv.GetGraph()

    procNode = lib_common.gUriGen.PidUri(pid)

    remSta = GetRemoteStack(pid)

    if remSta:
        callNodePrev = None

        for st in remSta:
            # == fichier=../essai.py line=6 module=<module>
            # == fichier=<string> line=1 module=<module>
            # == fichier=/tmp/tmpw14tgJ.py line=9 module=<module>
            sys.stderr.write("== fichier=%s line=%d module=%s\n" % ( st[0], st[1], st[2] ) )

            shortFilNam = st[0]
            lineNumber = st[1]
            moduleNam = st[2]

            # TODO: What is the full path name ?
            fileName = shortFilNam
            funcName = moduleNam

            # TODO: At each stage, should add the variables defined in each function call.

            # See process_gdbstack.py
            callNodePrev = survol_symbol.AddFunctionCall( grph, callNodePrev, procNode, funcName, fileName, lineNumber )

            if not callNodePrev:
                break
    else:
        sys.stderr.write("No stack visible\n")


    cgiEnv.OutCgiRdf()

if __name__ == '__main__':
    Main()
