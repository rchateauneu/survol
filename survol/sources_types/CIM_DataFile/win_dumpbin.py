#!/usr/bin/env python

"""
Dumpbin DLL symbols
"""

import os
import re
import sys
import logging

import lib_uris
import lib_util
import lib_common
from lib_properties import pc


# This script works only on a Windows executable or DLL etc...
Usable = lib_util.UsableWindowsBinary


# Dumpbin is widely available on Windows.
def Main():
    cgiEnv = lib_common.ScriptEnvironment()
    dll_file = cgiEnv.GetId()

    # The path containing the program dumpbin.exe should be a parameter.
    # It can for example be:
    # C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC\bin
    # c:/Program Files (x86)/Microsoft Visual Studio 10.0/VC/bin/amd64/
    dumpbin_exe = "dumpbin.exe"
    # For example: dll_file = "C:/Program Files (x86)/IBM/WebSphere MQ/bin/amqmdnet.dll"
    dumpbin_cmd = [dumpbin_exe, dll_file, "/exports"]

    logging.debug("dumpbin_cmd=%s", str(dumpbin_cmd))

    try:
        dumpbin_pipe = lib_common.SubProcPOpen(dumpbin_cmd)
    except Exception as exc:
        lib_common.ErrorMessageHtml("Windows error executing:" + " ".join(dumpbin_cmd) + ":" + str(exc))

    dumpbin_out, dumpbin_err = dumpbin_pipe.communicate()

    err_asstr = dumpbin_err.decode("utf-8")

    logging.debug("err_asstr=%s", str(err_asstr))

    # Converts to string for Python3.
    out_asstr = dumpbin_out.decode("utf-8")
    out_lines = out_asstr.split('\n')

    logging.debug("out_asstr=%s", str(out_asstr))

    grph = cgiEnv.GetGraph()

    node_dll = lib_uris.gUriGen.FileUri(dll_file)

    # C:\Users\jsmith>dumpbin.exe "C:/Program Files (x86)/NETGEAR/WNDA3100v3/ICSDHCP.dll" /exports
    # Microsoft (R) COFF/PE Dumper Version 12.00.31101.0
    # Copyright (C) Microsoft Corporation.  All rights reserved.
    #
    #
    # Dump of file C:/Program Files (x86)/NETGEAR/WNDA3100v3/ICSDHCP.dll
    #
    # File Type: DLL
    #
    #   Section contains the following exports for ICSDHCP.dll
    #
    #     00000000 characteristics
    #     50232972 time date stamp Thu Aug 09 04:07:30 2012
    #         0.00 version
    #            1 ordinal base
    #           17 number of functions
    #           17 number of names
    #
    #     ordinal hint RVA      name
    #
    #          15    0 00005E10 ?ICSDHCP_DisableICS@@YAIXZ
    #          16    1 00006650 ?ICSDHCP_GetAvailableDHCPSrvIP@@YAIQAE@Z
    #           9    2 000067C0 ICSDHCP_CheckIcsNodes
    #          10    3 000067F0 ICSDHCP_CheckIcsNodesEx
    #           8    4 000066F0 ICSDHCP_DisableDhcpServer
    #           5    5 00005E20 ICSDHCP_DisableICS
    #           6    6 00006020 ICSDHCP_EnableDhcpServer
    #          11    7 00006240 ICSDHCP_EnableDhcpServerEx
    #           3    8 00005A50 ICSDHCP_EnableICS
    #           4    9 00005C20 ICSDHCP_EnableICSP2P
    #           2    A 00005A40 ICSDHCP_FreeAdapterInfo
    #          14    B 00006850 ICSDHCP_FreeMemory
    #           1    C 00005950 ICSDHCP_GetAdaptersInfo
    #          17    D 000056F0 ICSDHCP_GetAdaptersInfoEx
    #          13    E 00006830 ICSDHCP_GetIPfromMACTableLookup
    #           7    F 000066D0 ICSDHCP_GetLeaseInfo
    #          12   10 00006810 ICSDHCP_IcsSwitchWan
    #
    #   Summary
    #
    #        11000 .data
    #        14000 .rdata
    #         6000 .reloc
    #         3000 .rsrc
    #        5E000 .text
    #
    for lin in out_lines:
        #        362  168 0111B5D0 ?CompareNoCase@AString@ole@@QBEHPBD@Z = ?CompareNoCase@AString@ole@@QBEHPBD@Z (public: int __thiscall ole:
        match_obj = re.match(r'^ *[0-9A-F]+ +[0-9A-F]+ +[0-9A-F]+ ([^ ]+)', lin)
        if match_obj:
            sym = match_obj.group(1)
            node_symbol = lib_uris.gUriGen.SymbolUri(sym, dll_file)
            grph.add((node_dll, pc.property_symbol_defined, node_symbol))

    cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_symbol_defined])


if __name__ == '__main__':
    Main()
