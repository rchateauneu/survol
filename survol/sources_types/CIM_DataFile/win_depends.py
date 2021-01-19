#!/usr/bin/env python

"""
Windows module dependencies (exe, dll, ocx, sys...) with Dependency Walker
"""

import os
import re
import sys
import time
import logging
import lib_util
import lib_win32
import lib_common
from lib_properties import pc

Usable = lib_util.UsableWindowsBinary

# Returns symbols associated to a DLL or an EXE file.

# depends.exe:
# http://www.dependencywalker.com/
# Dependency Walker is a free utility that scans any 32-bit or 64-bit
# Windows module (exe, dll, ocx, sys, etc.) and builds
# a hierarchical tree diagram of all dependent modules.
# http://www.dependencywalker.com/help/html/hidr_command_line_help.htm

# BEWARE: The PATH is different for Apache user and the results are less meaningful.
# TODO: HOW TO PROPERLY SET THE PATH ???


def Main():
    paramkey_group_by_dirs = "Group by directories"

    cgiEnv = lib_common.CgiEnv(parameters={paramkey_group_by_dirs: True})

    flag_group_by_dirs = bool(cgiEnv.get_parameters(paramkey_group_by_dirs))

    win_module = cgiEnv.GetId()

    lib_win32.CheckWindowsModule(win_module)

    # This has to be in the path. Is it the 32 bits or 64 bits one ?
    depends_bin = "depends.exe"

    logging.debug("depends_bin=%s", depends_bin)

    tmp_fil_obj = lib_util.TmpFile("depends")
    tmp_out_fil = tmp_fil_obj.Name
    args = [depends_bin, "/c", "/OC:", tmp_out_fil, win_module]

    logging.debug("Depends command=%s",str(args))

    grph = cgiEnv.GetGraph()

    node_dll = lib_common.gUriGen.FileUri(win_module)

    # TODO: Check the return value.
    # http://www.dependencywalker.com/help/html/hidr_command_line_help.htm
    p = lib_common.SubProcPOpen(args)
    nmap_last_output, nmap_err = p.communicate()
    for lin in nmap_last_output:
        continue
        # Wait for the end, otherwise the file will not be ready.

    try:
        logging.debug("Depends tmp_out_fil=%s", tmp_out_fil)
        input_file = open(tmp_out_fil, 'r')
    except Exception as exc:
        lib_common.ErrorMessageHtml("Caught " + str(exc) + " when processing:" + tmp_out_fil)

    # Status,Module,File Time Stamp,Link Time Stamp,File Size,Attr.,Link Checksum,Real Checksum,CPU,Subsystem,Symbols,Preferred Base,Actual Base,Virtual Size,Load Order,File Ver,Product Ver,Image Ver,Linker Ver,OS Ver,Subsystem Ver
    # ?,"MSVCR80D.DLL","Error opening file. The system cannot find the file specified (2).",,,,,,,,,,,,,,,,,,
    # D?,"XLCALL32.DLL","Error opening file. The system cannot find the file specified (2).",,,,,,,,,,,,,,,,,,
    # E6,"c:\windows\system32\ADVAPI32.DLL",2012-10-18 21:27:04,2012-10-18 21:27:12,876544,A,0x000D9B98,0x000D9B98,x64,Console,"CV",0x000007FF7FF10000,Unknown,0x000DB000,Not Loaded,6.1.7601.22137,6.1.7601.22137,6.1,9.0,6.1,6.1
    # E6,"c:\windows\system32\API-MS-WIN-CORE-CONSOLE-L1-1-0.DLL",2013-08-02 03:12:18,2013-08-02 03:12:52,3072,HA,0x000081B6,0x000081B6,x64,Console,"CV",0x0000000000400000,Unknown,0x00003000,Not Loaded,6.1.7601.18229,6.1.7601.18229,6.1,9.0,6.1,6.1

    # Used only if libraries are grouped by directory.
    dirs_to_nodes = {}

    for lin in input_file:
        # TODO: Beware of commas in file names!!!!! Maybe module shlex ?
        linargs = lin.split(',')
        module = linargs[1]
        # The library filename is enclosed in double-quotes, that we must remove.
        modul_nam = module[1:-1]
        lib_node = lib_common.gUriGen.SharedLibUri(modul_nam)

        # If the libraries are displayed in groups belnging to a dir, this is clearer.
        if flag_group_by_dirs:
            dir_nam = os.path.dirname(modul_nam)
            if dir_nam == "":
                dir_nam = "Unspecified dir"
            try:
                dir_nod = dirs_to_nodes[dir_nam]
            except KeyError:
                # TODO: Beware, in fact this is a directory.
                dir_nod = lib_common.gUriGen.FileUri(dir_nam)
                grph.add((node_dll, pc.property_library_depends, dir_nod))
                dirs_to_nodes[dir_nam] = dir_nod
            grph.add((dir_nod, pc.property_library_depends, lib_node))
        else:
            grph.add((node_dll, pc.property_library_depends, lib_node))

        if linargs[0] != '?':
            cpu = linargs[8]
            if cpu not in ["", "CPU"]:
                grph.add((node_dll, pc.property_library_cpu, lib_util.NodeLiteral(cpu)))

    # Temporary file removed by constructor.
    input_file.close()

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()

# Another solution:
# py2exe contains an extension module that determines binary dependencies:
#
# >>> from py2exe.py2exe_util import depends
# >>> impport pprint
# >>> pprint.pprint(depends(r"c:\windows\system32\notepad.exe").keys())
# ['C:\\WINDOWS\\system32\\USER32.dll',
# 'C:\\WINDOWS\\system32\\SHELL32.dll',