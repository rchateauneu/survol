#!/usr/bin/python

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

# TODO: On va virer "can_process_remote = True" et plutot en prendre la valeur dans le module courant.
CanProcessRemote = True

def Main():
	cgiEnv = lib_common.CgiEnv(can_process_remote = True)
	pid = int( cgiEnv.GetId() )
	machineName = cgiEnv.GetHost()

	grph = cgiEnv.GetGraph()

	if ( machineName == lib_util.currentHostname ) or ( not machineName ):
		#machName_or_None = None
		serverBox = lib_common.gUriGen
	else:
		#machName_or_None = machineName
		serverBox = lib_common.RemoteBox(machineName)

	node_process = serverBox.PidUri(pid)

	cnnct = lib_wmi.WmiConnect(machineName,"/root/cimv2")

	# lstProcs = cnnct.Win32_Process(Handle=pid)
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

	lstPropNames = [
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

	className = "CIM_Process"

	mapPropUnits = lib_wmi.WmiDictPropertiesUnit(cnnct, className)

	# There should be one process only.
	for wmiProc in lstProcs:
		sys.stderr.write("wmiProc=%s\n" % str(wmiProc))
		grph.add( ( node_process, pc.property_information, lib_common.NodeLiteral( wmiProc.Description ) ) )

		for prpProc in lstPropNames:
			valProc = getattr(wmiProc, prpProc)
			try:
				valUnit = mapPropUnits[prpProc]
			except KeyError:
				valUnit = ""
			valProcUnit = lib_util.AddSIUnit( valProc, valUnit )
			grph.add( ( node_process, lib_common.MakeProp(prpProc), lib_common.NodeLiteral( valProcUnit ) ) )

		parent_node_process = serverBox.PidUri(wmiProc.ParentProcessId)
		grph.add( ( node_process, pc.property_ppid, parent_node_process ) )

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
