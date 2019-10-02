#!/usr/bin/env python

"""
WBEM CIM_Process information.
"""

import sys
import lib_util
import lib_common
import lib_wbem
# from sources_types import CIM_Process
from lib_properties import pc

Usable = lib_util.UsableLinux

CanProcessRemote = True

def Main():
	# TODO: can_process_remote should be suppressed because it duplicates CanProcessRemote
	cgiEnv = lib_common.CgiEnv(can_process_remote = True)
	pid = int( cgiEnv.GetId() )
	machineName = cgiEnv.GetHost()

	grph = cgiEnv.GetGraph()

	if ( machineName == lib_util.currentHostname ) or ( not machineName ):
		serverBox = lib_common.gUriGen
	else:
		serverBox = lib_common.RemoteBox(machineName)

	cimomUrl = lib_wbem.HostnameToWbemServer(machineName)

	DEBUG("wbem_process_info.py currentHostname=%s pid=%d machineName=%s cimomUrl=%s",
            lib_util.currentHostname, pid, machineName, cimomUrl)

	connWbem = lib_wbem.WbemConnection(cimomUrl)

	nameSpace = "root/cimv2"
	try:
		instLists = connWbem.ExecQuery("WQL",'select * from CIM_Process  where Handle="%s"' % pid,nameSpace)
		# lstProc = connWbem.EnumerateInstances(ClassName="PG_UnixProcess",namespace="root/cimv2",Handle=pid)
	except:
		lib_common.ErrorMessageHtml("Error:"+str(sys.exc_info()))

	# This is taken from entity_wbem.py with much simplification.
	numInsts = len(instLists)

	className = "CIM_Process"
	dictProps = { "Handle" : pid }

	rootNode = lib_util.EntityClassNode( className, nameSpace, cimomUrl, "WBEM" )

	# There should be only one object, hopefully.
	for anInst in instLists:
		dictInst = dict(anInst)

		hostOnly = lib_util.EntHostToIp(cimomUrl)
		if lib_util.IsLocalAddress(hostOnly):
			uriInst = lib_common.gUriGen.UriMakeFromDict(className, dictProps)
		else:
			uriInst = lib_common.RemoteBox(hostOnly).UriMakeFromDict(className, dictProps)

		grph.add( ( rootNode, lib_common.MakeProp(className), uriInst ) )

		urlNamespace = lib_wbem.NamespaceUrl( nameSpace, cimomUrl, className )
		nodNamespace = lib_common.NodeUrl( urlNamespace )
		grph.add( ( rootNode, pc.property_cim_subnamespace , nodNamespace ) )

		# None properties are not printed.
		for inameKey in dictInst:
			inameVal = dictInst[inameKey]
			# TODO: If this is a reference, create a Node !!!!!!!
			if not inameVal is None:
				grph.add( ( uriInst, lib_common.MakeProp(inameKey), lib_common.NodeLiteral(inameVal) ) )

		# TODO: Call the method Associators(). Idem References().


	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
