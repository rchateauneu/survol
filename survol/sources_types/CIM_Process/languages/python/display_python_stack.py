#!/usr/bin/python

"""
Python stack
"""

import os
import re
import sys
import lib_util
import lib_common
from lib_properties import pc
from sources_types import linker_symbol as survol_symbol
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

        # Typical result:
        # [
        #     ["/home/rchateau/survol/tests/AnotherSampleDir/SampleSqlFile.py", 17, "<module>", "xx = sys.stdin.read(1)"],
        #     ["<string>", 1, "<module>", null],
        #     ["/tmp/tmpIcWP2j.py", 9, "<module>", "retobj = traceback.extract_stack()"]
        # ]
        for st in remSta:
            # == File=../essai.py line=6 module=<module>
            # == File=<string> line=1 module=<module>
            # == File=/tmp/tmpw14tgJ.py line=9 module=<module>
            DEBUG("File=%s line=%d module=%s", st[0], st[1], st[2] )

            shortFilNam = st[0]
            if shortFilNam == "<string>":
                shortFilNam = None
            lineNumber = st[1]
            moduleNam = st[2]
            if moduleNam == "<module>":
                moduleNam = None

            # TODO: What is the full path name ?
            fileName = shortFilNam
            funcName = moduleNam

            if funcName is None:
                # Maybe an intermediate call
                if fileName is None:
                    DEBUG("Intermediate call")
                    continue
                # Maybe the main program ?
                funcName = "__main__"

            # TODO: At each stage, should add the variables defined in each function call.

            # See process_gdbstack.py
            callNodePrev = survol_symbol.AddFunctionCall( grph, callNodePrev, procNode, funcName, fileName, lineNumber )

            if not callNodePrev:
                break
    else:
        WARNING("No stack visible")


    cgiEnv.OutCgiRdf()

if __name__ == '__main__':
    Main()
