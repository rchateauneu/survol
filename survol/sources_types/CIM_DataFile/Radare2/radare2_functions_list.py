#!/usr/bin/env python

"""
Functions extracted by Radare2
"""

import os
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

    node_exe_or_dll = lib_uris.gUriGen.FileUri(file_exe_or_dll)

    cmd_r2 = ['radare2','-A','-q','-c','"aflj"', file_exe_or_dll]
    logging.debug("cmd_r2=%s" % str(cmd_r2))

    r2_pipe = subprocess.Popen(cmd_r2, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    r2_output, r2_err = r2_pipe.communicate()
    rc = r2_pipe.returncode

    logging.debug("r2_err=%s" % r2_err)
    logging.debug("rc=%s" % rc)
    logging.debug("r2_output=%s" % r2_output)

    # {
    #     "offset":6442455744,
    #     "name":"sub.KERNEL32.dll_AcquireSRWLockShared_2c0",
    #     "size":305,
    #     "is-pure":false,
    #     "realsz":305,
    #     "stackframe":56,
    #     "calltype":"amd64",
    #     "cost":137,
    #     "cc":7,
    #     "bits":64,
    #     "type":"fcn",
    #     "nbbs":14,
    #     "edges":19,
    #     "ebbs":1,
    #     "minbound":"-2147478848",
    #     "maxbound":"-2147478543",
    #     "callrefs":[
    #         {"addr":6442455889,"type":"J","at":6442455801},
    #         {"addr":6442479744,"type":"C","at":6442455810},
    #         ...
    #         {"addr":6442456025,"type":"J","at":6442456018}],
    #     "datarefs":[6442504200,6442504200,6442504200,6442504200,6442504200],
    #     "codexrefs":[{"addr":6442462443,"type":"C","at":6442455744},
    #                  ...
    #                  {"addr":6442455907,"type":"J","at":6442456030}],
    #     "dataxrefs":[],
    #     "indegree":12,
    #     "outdegree":8,
    #     "nlocals":0,
    #     "nargs":11,
    #     "bpvars":[],
    #     "spvars":[{"name":"arg_8h","kind":"arg","type":"int","ref":{"base":"rsp", "offset":47244640264}},
    #               ...
    #               {"name":"arg_60h","kind":"arg","type":"int","ref":{"base":"rsp", "offset":47244640352}}],
    #     "regvars":[{"name":"arg6","kind":"reg","type":"int","ref":"r9"},
    #                ...
    #                {"name":"arg4","kind":"reg","type":"int","ref":"rcx"}],
    #     "difftype":"new"},
    # ...

    file_with_ext = os.path.basename(file_exe_or_dll)
    file_basename, file_extension = os.path.splitext(file_with_ext)

    def dll_base_name_to_path(dll_base_name):
        if dll_base_name.upper() == file_basename.upper():
            return file_exe_or_dll
        else:
            # Otherwise we have to find the library.
            dll_name = dll_base_name + ".dll"

            dllPath = lib_shared_lib_path.FindPathFromSharedLibraryName(dll_name)
            if dllPath:
                return dllPath
            else:
                # Maybe the directory of the shared library could not be found.
                return dll_name

    aflj_list = json.loads(r2_output)
    if aflj_list:
        for aflj_one in aflj_list:
            func_name = aflj_one["name"]

            if func_name.startswith("sym.imp."):
                # sym.ADVAPI32.dll_AuditComputeEffectivePolicyBySid
                # sym.imp.KERNEL32.dll_WriteFile
                # sym.imp.RPCRT4.dll_RpcBindingFree
                # sym.imp.msvcrt.dll_wcschr
                # sym.imp.ntdll.dll_NtClose
                func_name_split = func_name.split(".")
                dll_base_name = func_name_split[2]
                raw_entry_name = func_name_split[3]
                if not raw_entry_name.startswith("dll_"):
                    # Unexpected symbol name.
                    continue
                raw_entry_name = raw_entry_name[4:]

                dll_path_name = dll_base_name_to_path(dll_base_name)

                # If this is a local function. Uppercases for Windows only.
                sym_nod = lib_uris.gUriGen.SymbolUri(raw_entry_name, dll_path_name)

            elif func_name.startswith("sub."):
                func_name_split = func_name.split(".")

                # This could be "sub.0123456789abcdef_efc"
                if len(func_name_split) != 3:
                    continue

                dll_base_name = func_name_split[1]
                raw_entry_name_with_offset = func_name_split[2]
                raw_entry_name = raw_entry_name_with_offset
                if not raw_entry_name.startswith("dll_"):
                    # Unexpected symbol name.
                    continue
                raw_entry_name = raw_entry_name[4:]

                dll_path_name = dll_base_name_to_path(dll_base_name)

                # If this is a local function. Uppercases for Windows only.
                sym_nod = lib_uris.gUriGen.SymbolUri( raw_entry_name, dll_path_name )
            elif func_name.startswith("fcn."):
                # fcn.77c63e7e    Call_type    cdecl
                # fcn.77c63ed4    Call_type    cdecl
                # fcn.77c63eed    Call_type    cdecl
                sym_nod = lib_uris.gUriGen.SymbolUri( func_name, file_exe_or_dll )
            else:
                continue

            grph.add((sym_nod, lib_common.MakeProp("Call type"), lib_util.NodeLiteral(aflj_one["calltype"])))
            grph.add((node_exe_or_dll, pc.property_symbol_defined, sym_nod))

    cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_symbol_defined])


if __name__ == '__main__':
    Main()
