#!/usr/bin/env python

"""
Windows domain machines
"""

# http://timgolden.me.uk/python/win32_how_do_i/list_machines_in_a_domain.html

import os
import sys
import socket
import lib_util
import lib_common
from lib_properties import pc

def Main():
	cgiEnv = lib_common.CgiEnv()
	machineName = cgiEnv.GetId()
	if lib_util.IsLocalAddress( machineName ):
		machineName = None

	if not lib_util.isPlatformWindows:
		lib_common.ErrorMessageHtml("win32 Python library only on Windows platforms")

	try:
		import win32com.client
		import win32net
		import pywintypes
	except ImportError:
		lib_common.ErrorMessageHtml("win32 Python library not installed")

	grph = cgiEnv.GetGraph()

	try:
		# Parameters:
		# Name of remote server on which the function is to execute. If None, local computer.
		# Domain name. If None, name of the domain controller for the primary domain.
		# If machineName="LONW00052257.EURO.NET.INTRA", then it must be truncated to "LONW00052257"
		# Maybe this is a Netbios machine name ?? No idea, just make it work, for the moment.
		if machineName == None:
			machSplit = None
		else:
			machSplit = machineName.split('.')[0]
		WARNING("machineName:%s machSplit:%s",machineName,machSplit)
		domainController = win32net.NetGetDCName (machSplit, None)
	except pywintypes.error:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("NetGetDCName:machSplit=%s %s"%(machSplit,str(exc)))

	# This returns the domain name, for example "EURO".
	domainName = win32net.NetUserModalsGet (domainController, 2)['domain_name']
	DEBUG("Domain name:%s",domainName)
	DEBUG("Domaine Controller:%s",domainController)
	DEBUG("Info=%s",str(win32net.NetUserModalsGet (domainController, 2)))

	nodeDomain = lib_common.gUriGen.SmbDomainUri( domainName )
	nodeController = lib_common.gUriGen.HostnameUri( domainController )

	grph.add( (nodeDomain, pc.property_controller, nodeController ) )

	cnt = 0

	# Sounds like these are the machines in the domain...
	adsi = win32com.client.Dispatch ("ADsNameSpaces")
	nt = adsi.GetObject ("","WinNT:")
	result = nt.OpenDSObject ("WinNT://%s" % domainName, "", "", 0)
	result.Filter = ["computer"]

	for machine in result:
		# sys.stderr.write("Machine="+str(machine))
		if machine.Name[0] == '$':
			continue

		DEBUG("machineName=%s",machine.Name)
		nodeMachine = lib_common.gUriGen.HostnameUri( machine.Name )
		grph.add( (nodeDomain, pc.property_domain, nodeMachine ) )
		cnt += 1
		# TODO: It works fine until 1000 nodes, but after that takes ages to run. What can we do ?????
		# HARDCODE_LIMIT
		if cnt > 1000:
			WARNING("COULD NOT RUN IT TILL THE END")
			break

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
