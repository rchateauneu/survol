#!/usr/bin/env python

"""
Windows process loaded modules
"""

import re
import os
import sys
import logging

import lib_uris
import lib_util
import lib_common
from sources_types import CIM_Process
from sources_types import linker_symbol as survol_symbol
from sources_types.CIM_Process import CDB

Usable = lib_util.UsableWindows


# 76530000 76640000   kernel32   (export symbols)       C:\Windows\syswow64\kernel32.dll
# 76640000 7670c000   MSCTF      (deferred)
# 767a0000 767b9000   sechost    (deferred)
# 767c0000 76805000   WLDAP32    (deferred)
# 76810000 768ad000   USP10      (deferred)
# 768b0000 769ca000   urlmon     (deferred)
# 769d0000 769e2000   DEVOBJ     (deferred)
# 769f0000 76a47000   SHLWAPI    (deferred)
# 77300000 7730a000   LPK        (deferred)
# 77330000 774b0000   ntdll      (export symbols)       C:\Windows\SysWOW64\ntdll.dll

# 0:000> lm
# start    end        module name
# 00280000 002e9000   tibrv      (deferred)
# 75940000 7658b000   SHELL32    (deferred)
# 76590000 766a0000   kernel32   (export symbols)       C:\Windows\syswow64\kernel32.dll
# 766a0000 767bb000   WININET    (deferred)


def Main():
    cgiEnv = lib_common.ScriptEnvironment()
    try:
        the_pid = int(cgiEnv.GetId())
    except Exception:
        lib_common.ErrorMessageHtml("Must provide a pid")

    if not lib_util.isPlatformWindows:
        lib_common.ErrorMessageHtml("This works only on Windows platforms")

    # If cannot be the current pid, otherwise it will block.
    if the_pid == os.getpid():
        lib_common.ErrorMessageHtml("Cannot debug current process")

    grph = cgiEnv.GetGraph()

    # Starts a second session
    cdb_fil = lib_util.TmpFile("CdbCommand", "cdb")
    cdb_fd = open(cdb_fil.Name, "w")
    cdb_fd.write("lmv\n")  # List loaded modules, verbose mode.
    cdb_fd.write("qd\n")  # Quit and detach.
    cdb_fd.close()

    cdb_cmd = "cdb -p " + str(the_pid) + " -cf " + cdb_fil.Name

    proc_node = lib_uris.gUriGen.PidUri(the_pid)

    logging.debug("Starting cdb_cmd=%s", cdb_cmd)
    try:
        cdb_pipe = lib_common.SubProcPOpen(cdb_cmd)
    except WindowsError as exc:
        lib_common.ErrorMessageHtml("cdb not available: Caught:%s" % str(exc))

    logging.debug("Started cdb_cmd=%s", cdb_cmd)

    cdb_output, cdb_err = cdb_pipe.communicate()

    # Without decode, "TypeError: Type str does not support the buffer API"
    cdb_str =  cdb_output.decode("utf-8", "ignore")

    prop_loaded_module = lib_common.MakeProp("Loaded module")

    for dot_line in cdb_str.split('\n'):
        # moduleName=uDWM moduleStatus=deferred file_name=
        # dot_line=    Image path: C:\windows\system32\uDWM.dll
        # dot_line=    Image name: uDWM.dll
        # dot_line=    Timestamp:        Tue Jul 14 02:33:35 2009 (4A5BE06F)
        # dot_line=    CheckSum:         0005E9A4
        # dot_line=    ImageSize:        00057000
        # dot_line=    File version:     6.1.7600.16385
        # dot_line=    Product version:  6.1.7600.16385
        # dot_line=    File flags:       0 (Mask 3F)
        # dot_line=    File OS:          40004 NT Win32
        # dot_line=    File type:        2.0 Dll
        # dot_line=    File date:        00000000.00000000
        # dot_line=    Translations:     0409.04b0
        # dot_line=    CompanyName:      Microsoft Corporation
        # dot_line=    ProductName:      Microsoft Windows Operating System
        # dot_line=    InternalName:     udwm.dll
        # dot_line=    OriginalFilename: udwm.dll
        # dot_line=    ProductVersion:   6.1.7600.16385
        # dot_line=    FileVersion:      6.1.7600.16385 (win7_rtm.090713-1255)
        # dot_line=    FileDescription:  Microsoft Desktop Window Manager
        # dot_line=    LegalCopyright:    Microsoft Corporation. All rights reserved.

        match_lin = re.match(" *Image path: *(.*)", dot_line)
        if match_lin:

            file_name = match_lin.group(1)
            file_name = CDB.TestIfKnownDll(file_name)
            file_name = file_name.strip()
            file_name = lib_util.standardized_file_path(file_name)
            file_node = lib_uris.gUriGen.FileUri( file_name)
            grph.add((proc_node, prop_loaded_module, file_node))
            continue

        match_lin = re.match(" *CompanyName: *(.*)", dot_line)
        if match_lin:
            company_name = match_lin.group(1)
            grph.add((file_node, lib_common.MakeProp("Company Name"), lib_util.NodeLiteral(company_name)))
            continue

        match_lin = re.match(" *File OS: *(.*)", dot_line)
        if match_lin:
            file_os = match_lin.group(1)
            grph.add((file_node, lib_common.MakeProp("File OS"), lib_util.NodeLiteral(file_os)))
            continue

        match_lin = re.match(" *FileDescription: *(.*)", dot_line)
        if match_lin:
            file_description = match_lin.group(1)
            grph.add((file_node, lib_common.MakeProp("Description"), lib_util.NodeLiteral(file_description)))
            continue

    logging.debug("Parsed cdb result")

    CIM_Process.AddInfo(grph, proc_node, [the_pid])

    cgiEnv.OutCgiRdf("LAYOUT_RECT", [prop_loaded_module])


if __name__ == '__main__':
    Main()
