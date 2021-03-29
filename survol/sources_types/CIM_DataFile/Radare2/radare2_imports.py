#!/usr/bin/env python

"""
Import symbols detected by Radare2
"""

import json
import subprocess
import logging

import lib_uris
import lib_common
import lib_shared_lib_path
from lib_properties import pc


def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    file_exe_or_dll = cgiEnv.GetId()

    grph = cgiEnv.GetGraph()

    cmd_r2 = ['radare2', '-A', '-q', '-c', '"iij"', file_exe_or_dll]
    logging.debug("cmd_r2=%s\n" % str(cmd_r2))

    r2_pipe = subprocess.Popen(cmd_r2, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    r2_output, r2_err = r2_pipe.communicate()
    rc = r2_pipe.returncode

    logging.debug("r2_err=%s" % r2_err)
    logging.debug("rc=%s" % rc)
    logging.debug("r2_output=%s" % r2_output)

    #
    # {
    # "ordinal":1,
    # "bind":"NONE",
    # "type":"FUNC",
    # "name":"MSVCR120.dll__isnan",
    # "plt":4689968
    # },
    # ...

    iij_list = json.loads(r2_output)
    if iij_list:
        dict_dll_to_node = {}

        for iij_one in iij_list:
            # "SqlServerSpatial140.dll_?m_Points1@SampleDescriptor@@2QBNB"
            ii_func_name_raw = iij_one["name"]
            ii_other_short_dll_name, _, ii_func_name = ii_func_name_raw.partition(".")
            if ii_func_name.startswith("dll_"):
                ii_func_name = ii_func_name[4:]
            ii_plt = iij_one["plt"]
            ii_type = iij_one["type"]
            ii_bind = iij_one["bind"]

            try:
                node_exe_or_dll = dict_dll_to_node[ii_other_short_dll_name]
            except KeyError:
                ii_other_dll_name = ii_other_short_dll_name + ".dll"
                ie_other_dll_path = lib_shared_lib_path.FindPathFromSharedLibraryName(ii_other_dll_name)
                if ie_other_dll_path is None:
                    logging.warning("Cannot find library for ii_other_short_dll_name=%s", ii_other_dll_name)
                    ie_other_dll_path = ii_other_dll_name
                node_exe_or_dll = lib_uris.gUriGen.FileUri(ie_other_dll_path)
                dict_dll_to_node[ii_other_short_dll_name] = node_exe_or_dll

            sym_nod = lib_uris.gUriGen.SymbolUri(ii_func_name, ie_other_dll_path)

            grph.add((sym_nod, lib_common.MakeProp("plt"), lib_util.NodeLiteral(ii_plt)))
            grph.add((sym_nod, lib_common.MakeProp("type"), lib_util.NodeLiteral(ii_type)))
            grph.add((sym_nod, lib_common.MakeProp("bind"), lib_util.NodeLiteral(ii_bind)))
            grph.add((node_exe_or_dll, pc.property_symbol_defined, sym_nod))

    cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_symbol_defined])


if __name__ == '__main__':
    Main()
