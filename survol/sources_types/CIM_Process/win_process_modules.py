#!/usr/bin/env python

"""
Windows process modules
"""

import sys
import lib_util
import lib_common
from sources_types import CIM_Process
from lib_properties import pc

Usable = lib_util.UsableWindows

from ctypes import *

psapi = windll.psapi
kernel = windll.kernel32


def Main():
    cgiEnv = lib_common.ScriptEnvironment()
    pid = int(cgiEnv.GetId())

    # TODO: These are probably in win32com or a similar module.
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010

    grph = cgiEnv.GetGraph()

    node_process = lib_common.gUriGen.PidUri(pid)
    exec_node = CIM_Process.AddInfo(grph, node_process, [pid])

    #Get handle to the process based on PID
    hProcess = kernel.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if hProcess:
        ModuType = c_ulong * 512
        hModuleArr = ModuType()
        raw_cnt_modules = c_ulong()
        psapi.EnumProcessModules(hProcess, byref(hModuleArr), sizeof(hModuleArr), byref(raw_cnt_modules))
        nb_modules = int(raw_cnt_modules.value/sizeof(c_ulong()))
        if nb_modules >= 512:
            raise Exception("Disaster overrun")

        modname = c_buffer(256)
        for idx in range(0, nb_modules):
            ret_len = psapi.GetModuleFileNameExA(hProcess, hModuleArr[idx], modname, sizeof(modname))
            if ret_len == 0:
                # Maybe the string is empty.
                continue
            raw_filename_bytes = modname[:ret_len]
            raw_filename_as_str = raw_filename_bytes.decode()
            filnam = lib_util.standardized_file_path(raw_filename_as_str)

            lib_node = lib_common.gUriGen.SharedLibUri(filnam)
            grph.add((node_process, pc.property_library_depends, lib_node))

        kernel.CloseHandle(hProcess)

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
