#!/usr/bin/env python

"""
Processes returned by WBEM
"""

import sys
import lib_util
import lib_wbem
import lib_common
from lib_properties import pc

CanProcessRemote = True


def Main():

	# TODO: The type should really be an integer.
	cgiEnv = lib_common.CgiEnv(
					can_process_remote = True)

	# cimomUrl = cgiEnv.GetHost()
	# http://192.168.1.88
	machineName = cgiEnv.GetId()

	grph = cgiEnv.GetGraph()

	cimomUrl = lib_wbem.HostnameToWbemServer(machineName)

	DEBUG("wbem_hostname_processes.py cimomUrl=%s",cimomUrl)

	# If running on the local machine, pass the host as None otherwise authorization is checked
	# just like a remote machine, which means User Account Control (UAC) disabling,
	# and maybe setting LocalAccountTokenFilterPolicy=1
	if lib_util.IsLocalAddress( machineName ):
		#machName_or_None = None
		serverBox = lib_common.gUriGen
	else:
		#machName_or_None = machineName
		serverBox = lib_common.RemoteBox(machineName)

	# >>> conn = pywbem.WBEMConnection("http://192.168.1.88:5988" , ('pe***us','t*t*') )
	connWbem = lib_wbem.WbemConnection(cimomUrl)

	try:
		lstProc = connWbem.EnumerateInstances(ClassName="PG_UnixProcess",namespace="root/cimv2")
	except:
		lib_common.ErrorMessageHtml("Error:"+str(sys.exc_info()))

	# We should be using the class CMI_Process instead of PG_UnixProcess but it returns the error:
	# Python 2.7, pywbem.__version__ '0.8.0-dev'
	# >>> conn = pywbem.WBEMConnection("https://192.168.1.88:5989" , ('my-user','my-pass') )
	# >>> lst = conn.EnumerateInstanceNames(ClassName="CIM_Process",namespace="root/cimv2")
	# ...pywbem.cim_operations.CIMError: (1, u'CIM_ERR_FAILED: Error initializing CMPI MI /home/rchateau/TestProviderOpenLMI/tutorial_final/T
	# UT_UnixProcess.py, the following MI factory function(s) returned an error: _Generic_Create_InstanceMI, message was: cmpi:Traceback (
	# most recent call last):<br>  File "/usr/lib64/python2.7/site-packages/cmpi_pywbem_bindings.py", line 34, in <module><br>    from pyw
	# bem.cim_provider2 import ProviderProxy<br>ImportError: No module named cim_provider2<br>')


	# >>> lstProc[3].keys()
	# [u'OSCreationClassName', u'UserModeTime', u'Parameters', u'ExecutionState', u'ProcessGroupID', u'Priority', u'OtherExecutionDescript
	# ion', u'Handle', u'Description', u'RealUserID', u'CSCreationClassName', u'ProcessTTY', u'OSName', u'ProcessSessionID', u'CreationCla
	# ssName', u'WorkingSetSize', u'Name', u'CSName', u'ParentProcessID', u'KernelModeTime', u'Caption', u'ProcessNiceValue']

	# With a dictionary so node are created once only.
	Main.dictWbemPidToNode = {}

	def WbemPidToNode(procId):
		DEBUG("procId=%s",procId)
		try:
			return Main.dictWbemPidToNode[procId]
		except KeyError:
			node = serverBox.PidUri(procId)

			Main.dictWbemPidToNode[procId] = node
			return node

	for oneProc in lstProc:
		node_process = WbemPidToNode(oneProc["Handle"])
		parent_node_process = WbemPidToNode(oneProc["ParentProcessID"])

		grph.add( ( node_process, pc.property_ppid, parent_node_process ) )

		grph.add( ( node_process, pc.property_information, lib_common.NodeLiteral(oneProc["Caption"]) ) )

		if False:
			if oneProc["Caption"] != oneProc["Description"]:
				grph.add( ( node_process, lib_common.MakeProp("Description"), lib_common.NodeLiteral(oneProc["Description"]) ) )

			for prpNam in ["WorkingSetSize","KernelModeTime","ProcessNiceValue","OtherExecutionDescription"]:
				try:
					grph.add( ( node_process, lib_common.MakeProp(prpNam), lib_common.NodeLiteral(oneProc["prpNam"] ) ) )
				except KeyError:
					pass


	cgiEnv.OutCgiRdf()
	# cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
