#!/usr/bin/python

import os
import sys
import socket
import rdflib
import lib_common
from lib_common import pc

cgiEnv = lib_common.CgiEnv("Windows domain machines")

if not 'win' in sys.platform:
	lib_common.ErrorMessageHtml("win32 Python library only on Windows platforms")

try:
	import win32com.client
	import win32net
	import pywintypes
except ImportError:
	lib_common.ErrorMessageHtml("win32 Python library not installed")

grph = rdflib.Graph()

try:
	# TODO: Extends this to have machines as parameters.
	# domainController = win32net.NetGetDCName (None, None)
	# domainController = win32net.NetGetDCName (None, "")
	# ... throws: "Could not find domain controller for this domain."
	# domainController = win32net.NetGetDCName ("127.0.0.1", None)
	# domainController = win32net.NetGetDCName ("192.168.1.83", None)
	# domainController = win32net.NetGetDCName ("192.168.1.83", "")
	# ... throws: "The service has not been started."

	domainController = win32net.NetGetDCName ("", "")
except pywintypes.error:
	exc = sys.exc_info()[1]
	lib_common.ErrorMessageHtml(str(exc))

domainName = win32net.NetUserModalsGet (domainController, 2)['domain_name']
sys.stderr.write("Domain name:" + domainName + "\n")
sys.stderr.write("Domaine Controller:"+domainController + "\n")
sys.stderr.write("Info="+str(win32net.NetUserModalsGet (domainController, 2)) + "\n")

nodeDomain = lib_common.gUriGen.SmbDomainUri( domainName )
nodeController = lib_common.gUriGen.HostnameUri( domainController )

grph.add( (nodeDomain, pc.property_controller, nodeController ) )

sys.stderr.write("About to loop on machine\n")
cnt = 0

adsi = win32com.client.Dispatch ("ADsNameSpaces")
nt = adsi.GetObject ("","WinNT:")
result = nt.OpenDSObject ("WinNT://%s" % domainName, "", "", 0)
result.Filter = ["computer"]

for machine in result:
	# sys.stderr.write("Machine="+str(machine))
	if machine.Name[0] == '$':
		continue

	sys.stderr.write("machineName="+machine.Name+"\n")
	nodeMachine = lib_common.gUriGen.HostnameUri( machine.Name )
	grph.add( (nodeDomain, pc.property_domain, nodeMachine ) )
	cnt += 1
	# TODO: It works fine until 1000 nodes, but after that takes ages to run. What can we do ?????
	# HARDCODE_LIMIT
	if cnt > 1000:
		sys.stderr.write("COULD NOT RUN IT TILL THE END\n")
		break

cgiEnv.OutCgiRdf(grph)
