"""
Processes running MSDOS batches
"""

import os
import sys
import json
import tempfile
import psutil
import lib_util
from sources_types import CIM_Process


def Usable(entity_type, entity_ids_arr):
    """MS-Dos Batch processes"""

    # This tells if this is a Python process, by checking if this runs a python interpreter.
    # TODO: What id a plain C program starts a Python interpreter from inside ?
    # TODO: Should return an explanation message.
    is_windows = lib_util.UsableWindows(entity_type, entity_ids_arr)
    if not is_windows:
        return False

    pid_proc = entity_ids_arr[0]
    try:
        # Any error, no display.
        proc_obj = psutil.Process(int(pid_proc))
    except:
        return False

    # The command line can be something like:
    # C:\windows\system32\cmd.exe /c ""C:\Users\rchateau\Developpement\ReverseEngineeringApps\StartCgiServer.cmd" "
    # "cmd.exe" /s /k pushd "C:\Users\rchateau\Developpement\ReverseEngineeringApps\PythonStyle\Tests"
    # cmd  /help
    # "C:\windows\system32\cmd.exe"
    #

    # For all of these command lines, the path is always: "C:\Windows\System32\cmd.exe"
    try:
        proc_name = CIM_Process.PsutilProcToName(proc_obj)
    except Exception as exc:
        sys.stderr.write("Cannot get proc of:%s => %s\n" % (str(proc_obj), exc))

    return proc_name.endswith("cmd.exe")


