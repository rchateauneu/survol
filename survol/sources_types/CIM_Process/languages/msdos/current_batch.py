#!/usr/bin/env python

"""
Current batch file
"""

import os
import re
import sys
import logging
import lib_util
import lib_common
import getopt
from lib_properties import pc
from sources_types import CIM_Process
from sources_types.CIM_Process.languages import msdos as survol_msdos

Usable = survol_msdos.Usable


# CMD [/A | /U] [/Q] [/D] [/E:ON | /E:OFF] [/F:ON | /F:OFF] [/V:ON | /V:OFF]
#     [[/S] [/C | /K] string]
#
# /C      Carries out the command specified by string and then terminates
# /K      Carries out the command specified by string but remains
# /S      Modifies the treatment of string after /C or /K (see below)
# /Q      Turns echo off
# /D      Disable execution of AutoRun commands from registry (see below)
# /A      Causes the output of internal commands to a pipe or file to be ANSI
# /U      Causes the output of internal commands to a pipe or file to be
#         Unicode
# /T:fg   Sets the foreground/background colors (see COLOR /? for more info)
# /E:ON   Enable command extensions (see below)
# /E:OFF  Disable command extensions (see below)
# /F:ON   Enable file and directory name completion characters (see below)
# /F:OFF  Disable file and directory name completion characters (see below)
# /V:ON   Enable delayed environment variable expansion using ! as the
#         delimiter. For example, /V:ON would allow !var! to expand the
#         variable var at execution time.  The var syntax expands variables
#         at input time, which is quite a different thing when inside of a FOR
#         loop.
# /V:OFF  Disable delayed environment expansion.


def Main():
    cgiEnv = lib_common.ScriptEnvironment()
    pid_proc = int(cgiEnv.GetId())

    grph = cgiEnv.GetGraph()

    node_process = lib_common.gUriGen.PidUri(pid_proc)
    proc_obj = CIM_Process.PsutilGetProcObj(pid_proc)

    # Python 2
    # cmd_arr=['C:\\Python27\\python.exe', 'test_survol_client_library.py', '--debug', 'SurvolLocalTest.test_msdos_current_batch']
    # Python 3
    # cmd_arr=['C:\\Program Files (x86)\\Microsoft Visual Studio\\Shared\\Python36_64\\python.exe', 'test_survol_client_library.py', '--debug', 'SurvolLocalTest.test_msdos_current_batch']
    argv_array = CIM_Process.PsutilProcToCmdlineArray(proc_obj)
    logging.debug("argv_array=%s", str(argv_array))

    # This extracts the command file name and creates a node for it.
    for the_arg in argv_array[1:]:
        if the_arg[0] == "/":
            continue

        # Check if the file exists in the current directory.
        curr_pwd, err_msg = CIM_Process.PsutilProcCwd(proc_obj)
        if not curr_pwd:
            break

        all_dirs_to_search = [curr_pwd]

        env_path = CIM_Process.GetEnvVarProcess("PATH", proc_obj.pid)
        if env_path:
            all_dirs_to_search += env_path.split(";")

        # Now tries all possible dirs, starting with current directory.
        for a_dir in all_dirs_to_search:
            full_script_path = os.path.join(a_dir, the_arg)
            logging.debug("full_script_path=%s", full_script_path)
            if os.path.isfile(full_script_path):
                logging.debug("full_script_path=%s",full_script_path)
                script_node = lib_common.gUriGen.FileUri(full_script_path)
                grph.add( (node_process, pc.property_runs, script_node))
                break

        break
    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
