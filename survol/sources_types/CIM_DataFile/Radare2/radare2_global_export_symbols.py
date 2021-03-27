#!/usr/bin/env python

"""
Global export symbols (Radare2)
"""

import os
import json
import subprocess
import logging

import lib_uris
import lib_common
from lib_properties import pc


def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    file_exe_or_dll = cgiEnv.GetId()

    grph = cgiEnv.GetGraph()

    node_exe_or_dll = lib_uris.gUriGen.FileUri(file_exe_or_dll)

    cmd_r2 = ['radare2','-A','-q','-c','"iEj"', file_exe_or_dll]
    logging.debug("cmd_r2=%s" % str(cmd_r2))

    r2_pipe = subprocess.Popen(cmd_r2, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    r2_output, r2Err = r2_pipe.communicate()
    rc = r2_pipe.returncode

    logging.debug("r2Err=%s" % r2Err)
    logging.debug("rc=%s" % rc)
    logging.debug("r2_output=%s" % r2_output)

    #{
    #    "name":"SqlServerSpatial140.dll_?m_Points1@SampleDescriptor@@2QBNB",
    #    "demname":"",
    #    "flagname":"sym.SqlServerSpatial140.dll__m_Points1_SampleDescriptor__2QBNB",
    #    "ordinal":0,
    #    "bind":"GLOBAL",
    #    "size":0,
    #    "type":"FUNC",
    #    "vaddr":4691376,
    #    "paddr":490416},
    # ...

    i_ej_list = json.loads(r2_output)
    if i_ej_list:
        for i_ej_one in i_ej_list:
            # "SqlServerSpatial140.dll_?m_Points1@SampleDescriptor@@2QBNB"
            i_e_func_name_raw = i_ej_one["name"]
            _, _, i_e_func_name = i_e_func_name_raw.partition(".")
            if i_e_func_name.startswith("dll_"):
                i_e_func_name = i_e_func_name[4:]
            i_e_vaddr = i_ej_one["vaddr"]
            i_e_paddr = i_ej_one["paddr"]
            i_e_type = i_ej_one["type"]
            i_e_bind = i_ej_one["bind"]

            sym_nod = lib_uris.gUriGen.SymbolUri(i_e_func_name, file_exe_or_dll)

            grph.add((sym_nod, lib_common.MakeProp("vaddr"), lib_util.NodeLiteral(i_e_vaddr)))
            grph.add((sym_nod, lib_common.MakeProp("paddr"), lib_util.NodeLiteral(i_e_paddr)))
            grph.add((sym_nod, lib_common.MakeProp("type"), lib_util.NodeLiteral(i_e_type)))
            grph.add((sym_nod, lib_common.MakeProp("bind"), lib_util.NodeLiteral(i_e_bind)))
            grph.add((node_exe_or_dll, pc.property_symbol_defined, sym_nod))

    cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_symbol_defined])


if __name__ == '__main__':
    Main()
