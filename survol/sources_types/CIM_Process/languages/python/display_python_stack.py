#!/usr/bin/env python

"""
Python stack
"""

import os
import re
import sys
import logging

import lib_uris
import lib_util
import lib_common
from lib_properties import pc
from sources_types import linker_symbol as survol_symbol
from sources_types import CIM_Process
from sources_types.CIM_Process.languages import python as survol_python

Usable = survol_python.Usable


def Usable(entity_type, entity_ids_arr):
    """Python and Linux processes"""
    is_linux = lib_util.UsableLinux(entity_type, entity_ids_arr)
    if not is_linux:
        return False

    # This tells if it is a Python process.
    return CIM_Process.Usable(entity_type, entity_ids_arr)


def _get_remote_stack(the_pid):
    """
    These Python instructions will be executed by a debugger in the context of a Python process.
    The result is a vector of strings, the output of the execution.
    """
    vec_instructions = [
        'import json',
        'import traceback',
        'retobj = traceback.extract_stack()'
    ]
    obj_resu = survol_python.ExecInPythonDebugger(the_pid, vec_instructions)

    return obj_resu


def Main():
    cgiEnv = lib_common.ScriptEnvironment()
    pid = int(cgiEnv.GetId())

    grph = cgiEnv.GetGraph()

    proc_node = lib_uris.gUriGen.PidUri(pid)

    rem_sta = _get_remote_stack(pid)

    if rem_sta:
        call_node_prev = None

        # Typical result:
        # [
        #     ["/home/jsmith/survol/tests/SampleDirScripts/SampleSqlFile.py", 17, "<module>", "xx = sys.stdin.read(1)"],
        #     ["<string>", 1, "<module>", null],
        #     ["/tmp/tmpIcWP2j.py", 9, "<module>", "retobj = traceback.extract_stack()"]
        # ]
        for st in rem_sta:
            # == File=../essai.py line=6 module=<module>
            # == File=<string> line=1 module=<module>
            # == File=/tmp/tmpw14tgJ.py line=9 module=<module>
            logging.debug("File=%s line=%d module=%s", st[0], st[1], st[2])

            short_fil_nam = st[0]
            if short_fil_nam == "<string>":
                short_fil_nam = None
            line_number = st[1]
            module_nam = st[2]
            if module_nam == "<module>":
                module_nam = None

            # TODO: What is the full path name ?
            file_name = short_fil_nam
            func_name = module_nam

            if func_name is None:
                # Maybe an intermediate call
                if file_name is None:
                    logging.debug("Intermediate call")
                    continue
                # Maybe the main program ?
                func_name = "__main__"

            # TODO: At each stage, should add the variables defined in each function call.

            # See process_gdbstack.py
            call_node_prev = survol_symbol.AddFunctionCall(
                grph,
                call_node_prev,
                proc_node,
                func_name,
                file_name,
                line_number)

            if not call_node_prev:
                break
    else:
        logging.warning("No stack visible")

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
