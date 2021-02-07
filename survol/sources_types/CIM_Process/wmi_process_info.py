#!/usr/bin/env python

"""
WMI CIM_Process information.
"""

import sys
import lib_util
import lib_common
import lib_wmi
from sources_types import CIM_Process
from lib_properties import pc

Usable = lib_util.UsableWindows


# TODO: Remove "can_process_remote = True" and rather take the value in the current module ?
CanProcessRemote = True


def Main():
    cgiEnv = lib_common.CgiEnv(can_process_remote=True)
    pid = int(cgiEnv.GetId())
    machine_name = cgiEnv.GetHost()

    grph = cgiEnv.GetGraph()

    if (machine_name == lib_util.currentHostname) or not machine_name:
        server_box = lib_common.gUriGen
    else:
        server_box = lib_common.RemoteBox(machine_name)

    node_process = server_box.PidUri(pid)

    cnnct = lib_wmi.WmiConnect(machine_name, "/root/cimv2")

    # This also works when selecting from class Win32_Process.
    lstProcs = cnnct.CIM_Process(Handle=pid)

    # instance of Win32_Process
    # {
    #         Caption = "sqlwriter.exe";
    #         CreationClassName = "Win32_Process";
    #         CreationDate = "20161215105057.836987+000";
    #         CSCreationClassName = "Win32_ComputerSystem";
    #         CSName = "TITI";
    #         Description = "sqlwriter.exe";
    #         Handle = "1908";
    #         HandleCount = 101;
    #         KernelModeTime = "625000";
    #         Name = "sqlwriter.exe";
    #         OSCreationClassName = "Win32_OperatingSystem";
    #         OSName = "Microsoft Windows 8.1|C:\\Windows|\\Device\\Harddisk0\\Partition4";
    #         OtherOperationCount = "151";
    #         OtherTransferCount = "1316";
    #         PageFaults = 3735;
    #         PageFileUsage = 1508;
    #         ParentProcessId = 624;
    #         PeakPageFileUsage = 1860;
    #         PeakVirtualSize = "47603712";
    #         PeakWorkingSetSize = 5796;
    #         Priority = 8;
    #         PrivatePageCount = "1544192";
    #         ProcessId = 1908;
    #         QuotaNonPagedPoolUsage = 9;
    #         QuotaPagedPoolUsage = 72;
    #         QuotaPeakNonPagedPoolUsage = 10;
    #         QuotaPeakPagedPoolUsage = 72;
    #         ReadOperationCount = "0";
    #         ReadTransferCount = "0";
    #         SessionId = 0;
    #         ThreadCount = 2;
    #         UserModeTime = "625000";
    #         VirtualSize = "39182336";
    #         WindowsVersion = "6.3.9600";
    #         WorkingSetSize = "4780032";
    #         WriteOperationCount = "0";
    #         WriteTransferCount = "0";
    # };

    # In some circumstances - when the process is local ? - it can display the extra properties:

    #        CommandLine = "\"C:\\Windows\\system32\\SearchFilterHost
    #        ExecutablePath = "C:\\Windows\\system32\\SearchFilterHos

    lst_prop_names = [
        "CreationDate",
        "CSName",
        "HandleCount",
        "KernelModeTime",
        "Name",
        "OSName",
        "OtherOperationCount",
        "OtherTransferCount",
        "PageFaults",
        "PageFileUsage",
        "PeakPageFileUsage",
        "PeakVirtualSize",
        "PeakWorkingSetSize",
        "Priority",
        "PrivatePageCount",
        "QuotaNonPagedPoolUsage",
        "QuotaPagedPoolUsage",
        "QuotaPeakNonPagedPoolUsage",
        "QuotaPeakPagedPoolUsage",
        "ReadOperationCount",
        "ReadTransferCount",
        "SessionId",
        "ThreadCount",
        "UserModeTime",
        "VirtualSize",
        "WorkingSetSize",
        "WriteOperationCount",
        "WriteTransferCount"]

    class_name = "CIM_Process"

    map_prop_units = lib_wmi.WmiDictPropertiesUnit(cnnct, class_name)

    # There should be one process only.
    for wmi_proc in lstProcs:
        grph.add((node_process, pc.property_information, lib_util.NodeLiteral(wmi_proc.Description)))

        for prp_proc in lst_prop_names:
            val_proc = getattr(wmi_proc, prp_proc)
            try:
                val_unit = map_prop_units[prp_proc]
            except KeyError:
                val_unit = ""
            val_proc_unit = lib_util.AddSIUnit(val_proc, val_unit)
            grph.add((node_process, lib_common.MakeProp(prp_proc), lib_util.NodeLiteral(val_proc_unit)))

        parent_node_process = server_box.PidUri(wmi_proc.ParentProcessId)
        grph.add((node_process, pc.property_ppid, parent_node_process))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
