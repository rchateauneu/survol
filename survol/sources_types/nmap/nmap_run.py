#!/usr/bin/env python

"""
Nmap network exploration results
"""

import sys
import re
import socket
import xml.dom.minidom
import lib_util
import lib_common
from lib_properties import pc

def Main():
	paramkeyPortsRange = "Ports Range"
	paramkeyGraphDisplay = "Graph display"

	cgiEnv = lib_common.CgiEnv(
			{ paramkeyPortsRange : "22-443", paramkeyGraphDisplay: False} )

	# This is just a first experimentation with nmap.
	# This scans a couple of ports from the current host.
	# Ideally, the port range could be changed in edit mode of this script.
	# toto = "C:\\Program Files (x86)\\Nmap\\nmap.exe"
	# nmap_path="nmap"
	# The program nmap must be in the PATH.
	# args = ["nmap", '-oX', '-', '127.0.0.1', '-p', '22-443' ]

	portsRange = cgiEnv.get_parameters( paramkeyPortsRange )
	args = ["nmap", '-oX', '-', '127.0.0.1', '-p', portsRange ]
	# C:\Program Files (x86)\Nmap;

	isGraphDisplay = cgiEnv.get_parameters( paramkeyGraphDisplay )
	
	#try:
	p = lib_common.SubProcPOpen(args)
	#except WindowsError: # On Windows, this cannot find "FileNotFoundError"
	#	exc = sys.exc_info()[1]
	#	lib_common.ErrorMessageHtml("Cannot find nmap:"+str(exc)+". Maybe a dependency problem")
	#except FileNotFoundError:
	#	lib_common.ErrorMessageHtml("Cannot find nmap")

	grph = cgiEnv.GetGraph()

	( nmap_last_output, nmap_err) = p.communicate()

	dom = xml.dom.minidom.parseString(nmap_last_output)

	# sys.stderr.write(str(nmap_last_output))
	
	for dhost in dom.getElementsByTagName('host'):
		host = dhost.getElementsByTagName('address')[0].getAttributeNode('addr').value
		# print("host="+host)
		nodeHost = lib_common.gUriGen.HostnameUri( host )
		for dhostname in dhost.getElementsByTagName('hostname'):
			hostnam = dhostname.getAttributeNode('name').value
		#	print("        hostnam="+hostnam)
			grph.add( ( nodeHost, pc.property_hostname, lib_common.NodeLiteral( hostnam ) ) )

		#for dstatus in dhost.getElementsByTagName('status'):
			# status : up...
		#	print("        State="+dstatus.getAttributeNode('state').value )
		#	print("        Reason="+dstatus.getAttributeNode('reason').value )
		for dport in dhost.getElementsByTagName('port'):
			# protocol
			proto = dport.getAttributeNode('protocol').value
			# print("        proto="+proto)
			port = int(dport.getAttributeNode('portid').value)
			socketNode = lib_common.gUriGen.AddrUri( host, port, proto )

			if not isGraphDisplay:
				state = dport.getElementsByTagName('state')[0].getAttributeNode('state').value
				#sys.stderr.write("state="+state+"\n")
				grph.add( ( socketNode, lib_common.MakeProp("State"), lib_common.NodeLiteral(state) ) )
				
				reason = dport.getElementsByTagName('state')[0].getAttributeNode('reason').value
				#sys.stderr.write("reason="+reason)
				grph.add( ( socketNode, lib_common.MakeProp("Reason"), lib_common.NodeLiteral(reason) ) )
				# name if any
				#for dname in dport.getElementsByTagName('service'):
				#	name = dname.getAttributeNode('name').value
				#	print("            name="+name)

				#for dscript in dport.getElementsByTagName('script'):
				#	script_id = dscript.getAttributeNode('id').value
				#	script_out = dscript.getAttributeNode('output').value
				#	print("script_id="+script_id)
				#	print("script_out="+script_out)

			# BEWARE: Normally the LHS node should be a process !!!
			grph.add( ( nodeHost, pc.property_has_socket, socketNode ) )

	if isGraphDisplay:
		cgiEnv.OutCgiRdf()
	else:
		cgiEnv.OutCgiRdf( "LAYOUT_RECT", [pc.property_has_socket])

if __name__ == '__main__':
	Main()
