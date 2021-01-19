#!/usr/bin/env python

"""
WMI: Remote machine processes
"""


import sys
import logging
import lib_util
import lib_common
import lib_wmi
from lib_properties import pc

# If it cannot be imported, this is checked when loading the script.
import wmi


#instance of Win32_Process
#{
#        Caption = "SearchFilterHost.exe";
#        CommandLine = "\"C:\\Windows\\system32\\SearchFilterHost
#        CreationClassName = "Win32_Process";
#        CreationDate = "20150312142114.211889+000";
#        CSCreationClassName = "Win32_ComputerSystem";
#        CSName = "LONW00052257";
#        Description = "SearchFilterHost.exe";
#        ExecutablePath = "C:\\Windows\\system32\\SearchFilterHos
#        Handle = "26376";
#        HandleCount = 106;
#        KernelModeTime = "156001";
#        MaximumWorkingSetSize = 32768;
#        MinimumWorkingSetSize = 200;
#        Name = "SearchFilterHost.exe";
#        OSCreationClassName = "Win32_OperatingSystem";
#        OSName = "Microsoft Windows 7 Enterprise |C:\\Windows|\\
#        OtherOperationCount = "627";
#        OtherTransferCount = "4620";
#        PageFaults = 2206;
#        PageFileUsage = 3408;
#        ParentProcessId = 964;
#        PeakPageFileUsage = 3408;
#        PeakVirtualSize = "35500032";
#        PeakWorkingSetSize = 7340;
#        Priority = 4;
#        PrivatePageCount = "3489792";
#        ProcessId = 26376;
#        QuotaNonPagedPoolUsage = 9;
#        QuotaPagedPoolUsage = 96;
#        QuotaPeakNonPagedPoolUsage = 9;
#        QuotaPeakPagedPoolUsage = 96;
#        ReadOperationCount = "353";
#        ReadTransferCount = "29438";
#        SessionId = 0;
#        ThreadCount = 6;
#        UserModeTime = "156001";
#        VirtualSize = "35500032";
#        WindowsVersion = "6.1.7601";
#        WorkingSetSize = "7516160";
#        WriteOperationCount = "0";
#        WriteTransferCount = "0";
#};

CanProcessRemote = True


def Main():
    cgiEnv = lib_common.CgiEnv(can_process_remote=True)
    machine_name = cgiEnv.GetId()

    grph = cgiEnv.GetGraph()

    # If running on the local machine, pass the host as None otherwise authorization is checked
    # just like a remote machine, which means User Account Control (UAC) disabling,
    # and maybe setting LocalAccountTokenFilterPolicy=1
    if not machine_name or lib_util.IsLocalAddress(machine_name):
        mach_name_not_none = lib_util.currentHostname
        server_box = lib_common.gUriGen
    else:
        mach_name_not_none = machine_name
        server_box = lib_common.RemoteBox(machine_name)

    try:
        logging.debug("Explicit WMI connection machine_name=%s", mach_name_not_none)

        cnnct = lib_wmi.WmiConnect(mach_name_not_none, "/root/cimv2")

        #(wmiUser,wmiPass) = lib_credentials.GetCredentials("WMI",machine_name)
        #sys.stderr.write("machine_name= %wmiUser=%s\n" % ( machine_name, wmiUser ) )
        #cnnct = wmi.WMI(wmi=wmi.connect_server(server=machine_name, namespace="/root/cimv2", user=wmiUser, password=wmiPass))
    except Exception:
        lib_common.ErrorMessageHtml("WMI " + machine_name + " processes. Caught:" + str(sys.exc_info()))

    # With a dictionary so node are created once only.
    Main.dictPidToNode = {}

    def PidToNode(procId):
        try:
            return Main.dictPidToNode[procId]
        except KeyError:
            node = server_box.PidUri(procId)

            Main.dictPidToNode[procId] = node
            return node

    for processProperties in cnnct.Win32_Process ():

        node_process = PidToNode(processProperties.ProcessId)
        parent_node_process = PidToNode(processProperties.ParentProcessId)

        grph.add((node_process, pc.property_ppid, parent_node_process))
        #grph.add( ( node_process, pc.property_pid, lib_util.NodeLiteral(processProperties.ProcessId) ) )

        # >>> lp = cnnct.Win32_Process ()
        # >>> lp[0]
        # <_wmi_object: \\TITI\root\cimv2:Win32_Process.Handle="0">
        # >>> str(lp[0])
        # '\ninstance of Win32_Process\n{\n\tCaption = "System Idle Process";\n\tCreationClassName = "Win32_Process";\n\tCreationDate = "20161
        # 215105022.381553+000";\n\tCSCreationClassName = "Win32_ComputerSystem";\n\tCSName = "TITI";\n\tDescription = "System Idle Process";\
        # n\tHandle = "0";\n\tHandleCount = 0;\n\tKernelModeTime = "23403826406250";\n\tName = "System Idle Process";\n\tOSCreationClassName =
        #  "Win32_OperatingSystem";\n\tOSName = "Microsoft Windows 8.1|C:\\\\Windows|\\\\Device\\\\Harddisk0\\\\Partition4";\n\tOtherOperation
        # Count = "0";\n\tOtherTransferCount = "0";\n\tPageFaults = 1;\n\tPageFileUsage = 0;\n\tParentProcessId = 0;\n\tPeakPageFileUsage = 0;
        # \n\tPeakVirtualSize = "65536";\n\tPeakWorkingSetSize = 4;\n\tPriority = 0;\n\tPrivatePageCount = "0";\n\tProcessId = 0;\n\tQuotaNonP
        # agedPoolUsage = 0;\n\tQuotaPagedPoolUsage = 0;\n\tQuotaPeakNonPagedPoolUsage = 0;\n\tQuotaPeakPagedPoolUsage = 0;\n\tReadOperationCo
        # unt = "0";\n\tReadTransferCount = "0";\n\tSessionId = 0;\n\tThreadCount = 4;\n\tUserModeTime = "0";\n\tVirtualSize = "65536";\n\tWin
        # dowsVersion = "6.3.9600";\n\tWorkingSetSize = "4096";\n\tWriteOperationCount = "0";\n\tWriteTransferCount = "0";\n};\n'

        grph.add((node_process, pc.property_information, lib_util.NodeLiteral(processProperties.Caption)))
        if processProperties.Caption != processProperties.Description:
            grph.add((node_process, lib_common.MakeProp("Description"), lib_util.NodeLiteral(processProperties.Description)))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
