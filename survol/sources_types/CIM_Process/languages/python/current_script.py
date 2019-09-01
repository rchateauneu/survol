#!/usr/bin/env python

"""
Current script
"""

import os
import re
import sys
import lib_util
import lib_common
import getopt
from lib_properties import pc
from sources_types import CIM_Process
from sources_types.CIM_Process.languages import python as survol_python

Usable = survol_python.Usable

# usage: python [option] ... [-c cmd | -m mod | file | -] [arg] ...
# Options and arguments (and corresponding environment variables):
# -B     : don't write .py[co] files on import; also PYTHONDONTWRITEBYTECODE=x
# -c cmd : program passed in as string (terminates option list)
# -d     : debug output from parser; also PYTHONDEBUG=x
# -E     : ignore PYTHON* environment variables (such as PYTHONPATH)
# -h     : print this help message and exit (also --help)
# -i     : inspect interactively after running script; forces a prompt even
#          if stdin does not appear to be a terminal; also PYTHONINSPECT=x
# -m mod : run library module as a script (terminates option list)
# -O     : optimize generated bytecode slightly; also PYTHONOPTIMIZE=x
# -OO    : remove doc-strings in addition to the -O optimizations
# -R     : use a pseudo-random salt to make hash() values of various types be
#          unpredictable between separate invocations of the interpreter, as
#          a defense against denial-of-service attacks
# -Q arg : division options: -Qold (default), -Qwarn, -Qwarnall, -Qnew
# -s     : don't add user site directory to sys.path; also PYTHONNOUSERSITE
# -S     : don't imply 'import site' on initialization
# -t     : issue warnings about inconsistent tab usage (-tt: issue errors)
# -u     : unbuffered binary stdout and stderr; also PYTHONUNBUFFERED=x
#          see man page for details on internal buffering relating to '-u'
# -v     : verbose (trace import statements); also PYTHONVERBOSE=x
#          can be supplied multiple times to increase verbosity
# -V     : print the Python version number and exit (also --version)
# -W arg : warning control; arg is action:message:category:module:lineno
#          also PYTHONWARNINGS=arg
# -x     : skip first line of source, allowing use of non-Unix forms of #!cmd
# -3     : warn about Python 3.x incompatibilities that 2to3 cannot trivially fix
# file   : program read from script file
# -      : program read from stdin (default; interactive mode if a tty)
# arg ...: arguments passed to program in sys.argv[1:]
#
# Other environment variables:
# PYTHONSTARTUP: file executed on interactive startup (no default)
# PYTHONPATH   : ';'-separated list of directories prefixed to the
#                default module search path.  The result is sys.path.
# PYTHONHOME   : alternate <prefix> directory (or <prefix>;<exec_prefix>).
#                The default module search path uses <prefix>\lib.
# PYTHONCASEOK : ignore case in 'import' statements (Windows).
# PYTHONIOENCODING: Encoding[:errors] used for stdin/stdout/stderr.
# PYTHONHASHSEED: if this variable is set to 'random', the effect is the same
#    as specifying the -R option: a random value is used to seed the hashes of
#    str, bytes and datetime objects.  It can also be set to an integer
#    in the range [0,4294967295] to get hash values with a predictable seed.

# Find the file, given PYTHONPATH and the process current directory.
def PyFilNode(proc_obj,filNam,ignoreEnvs):
    fullFileName = None

    if os.path.isabs(filNam):
        fullFileName = filNam
    else:
        # Check if the file exists in the current directory.
        currPwd,errMsg = CIM_Process.PsutilProcCwd(proc_obj)
        if not currPwd:
            DEBUG("PyFilNode: %s",errMsg)
            return None

        allDirsToSearch = [ currPwd ]

        # With this option, do not use environment variable.
        if not ignoreEnvs:
            pathPython = CIM_Process.GetEnvVarProcess("PYTHONPATH",proc_obj.pid)
            if pathPython:
                pathPythonSplit = pathPython.split(":")
                allDirsToSearch += pathPythonSplit

        # Now tries all possible dirs, starting with current directory.
        for aDir in allDirsToSearch:
            fullPath = os.path.join(aDir,filNam)
            if os.path.isfile(fullPath):
                fullFileName = fullPath
                break

    if fullFileName:
        filNode = lib_common.gUriGen.FileUri( fullFileName )
        return filNode
    else:
        return None


def AddNodesFromCommandLine(argvArray, grph, node_process, proc_obj):
    # First, extracts the executable.
    # This applies to Windows only.
    idxCommand = 0
    lenCommand = len(argvArray)
    if lib_util.isPlatformWindows:
        if argvArray[0].endswith("cmd.exe"):
            idxCommand += 1

        while idxCommand < lenCommand and argvArray[idxCommand].startswith("/"):
            idxCommand += 1

    # Now, the current argument should be a Python command.
    if argvArray[idxCommand].find("python") < 0:
        DEBUG("Command does not contain Python:%s",str(argvArray))
        return

    # Now removes options of Python command.
    # Options and arguments (and corresponding environment variables):
    # -B     : don't write .py[co] files on import; also PYTHONDONTWRITEBYTECODE=x
    # -c cmd : program passed in as string (terminates option list)
    # -d     : debug output from parser; also PYTHONDEBUG=x
    # -E     : ignore PYTHON* environment variables (such as PYTHONPATH)
    # -h     : print this help message and exit (also --help)
    # -i     : inspect interactively after running script; forces a prompt even
    #          if stdin does not appear to be a terminal; also PYTHONINSPECT=x
    # -m mod : run library module as a script (terminates option list)
    # -O     : optimize generated bytecode slightly; also PYTHONOPTIMIZE=x
    # -OO    : remove doc-strings in addition to the -O optimizations
    # -R     : use a pseudo-random salt to make hash() values of various types be
    #          unpredictable between separate invocations of the interpreter, as
    #          a defense against denial-of-service attacks
    # -Q arg : division options: -Qold (default), -Qwarn, -Qwarnall, -Qnew
    # -s     : don't add user site directory to sys.path; also PYTHONNOUSERSITE
    # -S     : don't imply 'import site' on initialization
    # -t     : issue warnings about inconsistent tab usage (-tt: issue errors)
    # -u     : unbuffered binary stdout and stderr; also PYTHONUNBUFFERED=x
    #          see man page for details on internal buffering relating to '-u'
    # -v     : verbose (trace import statements); also PYTHONVERBOSE=x
    #          can be supplied multiple times to increase verbosity
    # -V     : print the Python version number and exit (also --version)
    # -W arg : warning control; arg is action:message:category:module:lineno
    #          also PYTHONWARNINGS=arg
    # -x     : skip first line of source, allowing use of non-Unix forms of #!cmd
    # -3     : warn about Python 3.x incompatibilities that 2to3 cannot trivially fix
    # file   : program read from script file
    # -      : program read from stdin (default; interactive mode if a tty)
    # arg ...: arguments passed to program in sys.argv[1:]
    ignoreEnvs = False
    idxCommand += 1
    while idxCommand < lenCommand:
        currArg = argvArray[idxCommand]
        if currArg.startswith("-"):
            if currArg == '-E':
                ignoreEnvs = True
            elif currArg in ["-Q","-W"] :
                # Extra argument we do not want.
                idxCommand += 1
            elif currArg in ["-m"] :
                # TODO: Followed by a module.
                pass
            elif currArg in ["-c"] :
                # TODO: Followed by Python code: Cannot anything.
                return
            idxCommand += 1
        else:
            filNode = PyFilNode(proc_obj, currArg, ignoreEnvs)
            if filNode:
                grph.add( ( node_process, pc.property_runs, filNode ) )
            break
        idxCommand += 1

def Main():
    cgiEnv = lib_common.CgiEnv()
    pidProc = int( cgiEnv.GetId() )

    grph = cgiEnv.GetGraph()

    node_process = lib_common.gUriGen.PidUri(pidProc)
    proc_obj = CIM_Process.PsutilGetProcObj(int(pidProc))

    # Now we are parsing the command line.
    argvArray = CIM_Process.PsutilProcToCmdlineArray(proc_obj)

    # On Windows, this could be:
    # [u'C:\\windows\\system32\\cmd.exe', u'/c', u'C:\\Python27\\python.exe', u'AnotherSampleDir\\SampleSqlFile.py']
    DEBUG("argvArray=%s",str(argvArray))

    # The difficulty is that filenames with spaces are split.
    # Therefore, entire filenames must be rebuilt from pieces.

    AddNodesFromCommandLine(argvArray,grph,node_process,proc_obj)


    cgiEnv.OutCgiRdf()

if __name__ == '__main__':
    Main()
