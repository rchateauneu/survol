"""
Python processes
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
    """Python processes"""

    pidProc = entity_ids_arr[0]
    try:
        # Any error, no display.
        proc_obj = CIM_Process.PsutilGetProcObjNoThrow(int(pidProc))
    except:
        return False

    cmd_line = CIM_Process.PsutilProcToCmdline(proc_obj)

    cmdlinSplit = cmd_line.split(" ")
    execNam = cmdlinSplit[0]
    basNam = os.path.basename(execNam)

    # This is a python process because of the executable.
    return basNam.startswith("python")



# This is more than strongly inspired from the module pyrasite.


# cdb -p pid
# https://blogs.msdn.microsoft.com/oldnewthing/20070427-00/?p=27083
# .call
# .detach
# 0:001> x python27!PyGI*
# 00000000`1e136060 python27!PyGILState_GetThisThreadState (<no parameter info>)
# 00000000`1e136080 python27!PyGILState_Release (<no parameter info>)
# 00000000`1e136450 python27!PyGILState_Ensure (<no parameter info>)
# 0:001> .call python27!PyGILState_Ensure()
#                                       ^ Symbol not a function in '.call python27!PyGILState_Ensure()'
#
#:001> x msvcr90!pri*
#...
#00000000`70ca274c MSVCR90!printf (<no parameter info>)
#...
#0:001> .call msvcr90!printf("hh")
#                          ^ Symbol not a function in '.call msvcr90!printf("hh")'
#That error message is the debugger's somewhat confusing way of saying:
#"I don't have enough information available to make that function call."
#
def ExecInPythonDebuggerWindows(my_pid,vecInstructions):
	return []

# This creates a Python file executing some commands.
# The result must be displayed on the debugger's window.
def ExecInPythonDebuggerLinux(my_pid,vecInstructions):
    filnaPair = tempfile.mkstemp(suffix=".py",text=True)
    filna = filnaPair[1]

    # This file will contain the result of the execution.
    outFilNaPair = tempfile.mkstemp(suffix=".dat",text=True)
    outFilFd = outFilNaPair[0]
    # outFilFd.close()
    outFilNa = outFilNaPair[1]

    fi = open(filna,"w")
    fi.write("import sys\n")
    fi.write("tmpout = sys.stdout\n")
    fi.write("tmperr = sys.stderr\n")
    fi.write("filout = open('%s','w')\n" % outFilNa )
    fi.write("sys.stdout = filout\n")
    fi.write("sys.stderr = filout\n")

    for instFi in vecInstructions:
        fi.write("%s\n"% instFi)

    fi.write("sys.stdout = tmpout\n")
    fi.write("sys.stderr = tmperr\n")
    fi.write("filout.close()\n")

    fi.close()

    gdb_cmds_filout = [
	'PyGILState_Ensure()',
	'PyRun_SimpleString("execfile(\\"%s\\")")' % filna,
	'PyGILState_Release($1)',
	]

    big_args = ' '.join(["-eval-command='call %s'" % cmd for cmd in gdb_cmds_filout])
    sys.stderr.write("big_args=%s\n\n" % big_args)

	# TODO: See process_gdbstack.py which similarly runs a gdb command.
    cmdline = 'gdb -p %d -batch %s' % (my_pid, big_args )
    sys.stderr.write("cmdline=%s\n\n" % cmdline)

    # TODO: Must use lib_common.SubProcPOpen
    # TODO is shell=True necessary ?????
    # subprocess.call(cmdline, shell=True)
    SubProcCall(cmdline)

    filOutDat = open(outFilNa,"r")
    vecResult = filOutDat.readlines();
    filOutDat.close()

    return vecResult


def ExecInPythonDebugger(thePid, vecInstructions):
    vecInstructions.append( 'print(json.dumps(retobj))' )

    if sys.platform.startswith("win"):
        DebuggerPython = ExecInPythonDebuggerWindows
    else:
        DebuggerPython = ExecInPythonDebuggerLinux

    vecResu = DebuggerPython(thePid,vecInstructions)
    if len(vecResu) != 1:
        sys.stderr.write("Err:%s\n" % str(vecResu) )
        return None

    strResu = vecResu[0]
    objResu = json.loads(strResu)
    return objResu


# Print the stack content with this:
# sys._getframe(1).f_code.co_name
