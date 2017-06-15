#!/usr/bin/python

"""
Current batch file
"""

import os
import re
import sys
import psutil
import rdflib
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
    cgiEnv = lib_common.CgiEnv()
    pidProc = int( cgiEnv.GetId() )

    grph = cgiEnv.GetGraph()

    node_process = lib_common.gUriGen.PidUri(pidProc)
    proc_obj = psutil.Process(pidProc)

    # Now we are parsing the command line.
    cmd_line = CIM_Process.PsutilProcToCmdline(proc_obj)

    sys.stderr.write("cmd_line=%s\n"%str(cmd_line))

    # Similar to split, but ignores white spaces in double quotes.
    argvArray = re.findall(r'(?:[^\s "]|"(?:\\.|[^"])*")+', cmd_line )

    sys.stderr.write("argvArray=%s\n"%str(argvArray))

    # This extracts the command file name and creates a node for it.
    for theArg in argvArray[1:]:
        if theArg[0] == "/":
            continue

        # Check if the file exists in the current directory.
        currPwd,errMsg = CIM_Process.PsutilProcCwd(proc_obj)
        if not currPwd:
            sys.stderr.write("PyFilNode: %s\n"%errMsg)
            break

        allDirsToSearch = [ currPwd ]

        envPath = CIM_Process.GetEnvVarProcess("PATH",proc_obj.pid)
        if envPath:
            allDirsToSearch += envPath.split(";")

        # Now tries all possible dirs, starting with current directory.
        for aDir in allDirsToSearch:
            fullScriptPath = os.path.join(aDir,theArg)
            if os.path.isfile(fullScriptPath):
                sys.stderr.write("fullScriptPath=%s\n"%fullScriptPath)
                scriptNode = lib_common.gUriGen.FileUri( fullScriptPath )
                grph.add( ( node_process, pc.property_runs, scriptNode ) )
                break

        break



    cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
    Main()
