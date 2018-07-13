"""
Processes running MSDOS batches
"""

import os
import sys
import json
import lib_util
import tempfile
from sources_types import CIM_Process

# This tells if this is a Python process, by checking if this runs a python interpreter.
# TODO: What id a plain C program starts a Python interpreter from inside ?
def Usable(entity_type,entity_ids_arr):
    """MS-Dos Batch processes"""

    isWindows = lib_util.UsableWindows(entity_type,entity_ids_arr)
    if not isWindows:
        return False

    pidProc = entity_ids_arr[0]
    try:
        # Any error, no display.
        proc_obj = CIM_Process.PsutilGetProcObjNoThrow(int(pidProc))
    except:
        return False

    # The command line can be something like:
    # C:\windows\system32\cmd.exe /c ""C:\Users\rchateau\Developpement\ReverseEngineeringApps\StartCgiServer.cmd" "
    # "cmd.exe" /s /k pushd "C:\Users\rchateau\Developpement\ReverseEngineeringApps\PythonStyle\Tests"
    # cmd  /help
    # "C:\windows\system32\cmd.exe"
    #
    # cmd_line = CIM_Process.PsutilProcToCmdline(proc_obj)
    # cmdlinSplit = cmd_line.split(" ")
    # execNam = cmdlinSplit[0]

    # For all of these command lines, the path is always: "C:\Windows\System32\cmd.exe"
    procName = CIM_Process.PsutilProcToName(proc_obj)

    return procName == "cmd.exe"


