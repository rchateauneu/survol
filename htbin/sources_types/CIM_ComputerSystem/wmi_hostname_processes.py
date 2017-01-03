#!/usr/bin/python

"""
WMI: Remote machine processes
"""


import sys
import rdflib
import lib_util
import lib_common
from lib_common import pc

try:
	import wmi
except ImportError:
	lib_common.ErrorMessageHtml("wmi library cannot be imported")


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

def Main():
	cgiEnv = lib_common.CgiEnv(can_process_remote = True)
	machineName = cgiEnv.GetId()

	grph = rdflib.Graph()

	# If running on the local machine, pass the host as None otherwise authorization is checked
	# just like a remote machine, which means User Account Control (UAC) disabling,
	# and maybe setting LocalAccountTokenFilterPolicy=1
	if machineName == lib_util.currentHostname:
		machName_or_None = None
	else:
		machName_or_None = machineName

	try:
		c = wmi.WMI (machName_or_None)
	except Exception:
		lib_common.ErrorMessageHtml("WMI " + machineName + " processes. Caught:" + str(sys.exc_info()) )

	# With a dictionary so node are created once only.
	Main.dictPidToNode = {}

	def PidToNode(pid):
		try:
			return Main.dictPidToNode[pid]
		except KeyError:
			node = lib_common.gUriGen.PidUri(pid)
			Main.dictPidToNode[pid] = node
			return node

	for process in c.Win32_Process ():

		node_process = PidToNode(process.ProcessId)
		parent_node_process = PidToNode(process.ParentProcessId)

		grph.add( ( node_process, pc.property_ppid, parent_node_process ) )
		grph.add( ( node_process, pc.property_pid, rdflib.Literal(process.ProcessId) ) )

		# All the rest is not needed yet, there would be too much things to display.
		#grph.add( ( node_process, pc.property_command, rdflib.Literal(process.CommandLine) ) )
		#
		#exec_name = process.ExecutablePath
		#if exec_name != None:
		#	exec_node = lib_common.gUriGen.FileUri( exec_name.replace('\\','/') )
		#	grph.add( ( node_process, pc.property_runs, exec_node ) )

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()
