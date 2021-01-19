"""
Python processes
"""

import os
import sys
import json
import logging
import psutil
import lib_util
import lib_common
import tempfile
from sources_types import CIM_Process


# This tells if this is a Python process, by checking if this runs a python interpreter.
# TODO: What id a plain C program starts a Python interpreter from inside ?
def Usable(entity_type, entity_ids_arr):
    """Python processes"""

    pid_proc = entity_ids_arr[0]
    try:
        # Any error, no display.
        proc_obj = psutil.Process(int(pid_proc))
    except:
        return False

    cmd_line = CIM_Process.PsutilProcToCmdline(proc_obj)

    cmdlin_split = cmd_line.split(" ")
    exec_nam = cmdlin_split[0]
    bas_nam = os.path.basename(exec_nam)

    # This is a python process because of the executable.
    return bas_nam.startswith("python")

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
def _exec_in_python_debugger_windows(my_pid, vec_instructions):
    return []


def _exec_in_python_debugger_linux(my_pid, vec_instructions):
    """
    This creates a Python file executing some commands.
    The result must be displayed on the debugger's window.
    """
    filna_pair = tempfile.mkstemp(suffix=".py", text=True)
    filna = filna_pair[1]
    logging.debug("_exec_in_python_debugger_linux filna=%s", filna)

    # This file will contain the result of the execution.
    out_fil_na_pair = tempfile.mkstemp(suffix=".dat", text=True)
    out_fil_fd = out_fil_na_pair[0]
    # out_fil_fd.close()
    out_fil_na = out_fil_na_pair[1]

    fi = open(filna,"w")
    fi.write("import sys\n")
    fi.write("tmpout = sys.stdout\n")
    fi.write("tmperr = sys.stderr\n")
    fi.write("filout = open('%s','w')\n" % out_fil_na)
    fi.write("sys.stdout = filout\n")
    fi.write("sys.stderr = filout\n")

    for instFi in vec_instructions:
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
    logging.debug("big_args=%s\n", big_args)

    # TODO: See process_gdbstack.py which similarly runs a gdb command.
    cmdline = 'gdb -p %d -batch %s' % (my_pid, big_args)
    logging.debug("cmdline=%s out_fil_na=%s\n", cmdline, out_fil_na)

    lib_common.SubProcCall(cmdline)

    fil_out_dat = open(out_fil_na, "r")
    vec_result = fil_out_dat.readlines()
    fil_out_dat.close()

    return vec_result


def ExecInPythonDebugger(the_pid, vec_instructions):
    vec_instructions.append('print(json.dumps(retobj))')

    if lib_util.isPlatformWindows:
        debugger_python = _exec_in_python_debugger_windows
    else:
        debugger_python = _exec_in_python_debugger_linux

    vec_resu = debugger_python(the_pid, vec_instructions)
    if len(vec_resu) != 1:
        logging.warning("ExecInPythonDebugger: Err:%s", str(vec_resu) )
        return None

    str_resu = vec_resu[0]
    obj_resu = json.loads(str_resu)
    return obj_resu

