#!/usr/bin/python

import sys
import re
import socket
import rdflib
import subprocess
import xml.dom.minidom

import lib_common
from lib_properties import pc

paramkeyPortsRange = "Ports Range"

cgiEnv = lib_common.CgiEnv(
		"Nmap network exploration results",
		"http://nmap.org/images/nmap-logo-64px.png",
		{ paramkeyPortsRange : "22-443" } )

# This is just a first experimentation with nmap.
# This scans a couple of ports from the current host.
# Ideally, the port range could be changed in edit mode of this script.
# toto = "C:\\Program Files (x86)\\Nmap\\nmap.exe"
# nmap_path="nmap"
# The program nmap must be in the PATH.
# args = ["nmap", '-oX', '-', '127.0.0.1', '-p', '22-443' ]

portsRange = cgiEnv.GetParameters( paramkeyPortsRange )
args = ["nmap", '-oX', '-', '127.0.0.1', '-p', portsRange ]
# C:\Program Files (x86)\Nmap;

try:
	p = subprocess.Popen(args, bufsize=100000, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
except WindowsError: # On Windows, this cannot find "FileNotFoundError"
	exc = sys.exc_info()[1]
	lib_common.ErrorMessageHtml("Cannot find nmap:"+str(exc)+". Maybe a dependency problem")
except FileNotFoundError:
	lib_common.ErrorMessageHtml("Cannot find nmap")
	
grph = rdflib.Graph()

( nmap_last_output, nmap_err) = p.communicate()

dom = xml.dom.minidom.parseString(nmap_last_output)

for dhost in dom.getElementsByTagName('host'):
	host = dhost.getElementsByTagName('address')[0].getAttributeNode('addr').value
	# print("host="+host)
	nodeHost = lib_common.gUriGen.HostnameUri( host )
	for dhostname in dhost.getElementsByTagName('hostname'):
		hostnam = dhostname.getAttributeNode('name').value
	#	print("        hostnam="+hostnam)
		grph.add( ( nodeHost, pc.property_hostname, rdflib.Literal( hostnam ) ) )

	#for dstatus in dhost.getElementsByTagName('status'):
		# status : up...
	#	print("        State="+dstatus.getAttributeNode('state').value )
	#	print("        Reason="+dstatus.getAttributeNode('reason').value )
	for dport in dhost.getElementsByTagName('port'):
		# protocol
		proto = dport.getAttributeNode('protocol').value
		# print("        proto="+proto)
		# port number converted as integer
		port =  int(dport.getAttributeNode('portid').value)
		# print("        port=%d" % port)
		# state of the port
		#state = dport.getElementsByTagName('state')[0].getAttributeNode('state').value
		#print("        state="+state)
		# reason
		#reason = dport.getElementsByTagName('state')[0].getAttributeNode('reason').value
		#print("        reason="+reason)
		# name if any
		#for dname in dport.getElementsByTagName('service'):
		#	name = dname.getAttributeNode('name').value
		#	print("            name="+name)

		#for dscript in dport.getElementsByTagName('script'):
		#	script_id = dscript.getAttributeNode('id').value
		#	script_out = dscript.getAttributeNode('output').value
		#	print("script_id="+script_id)
		#	print("script_out="+script_out)

		socketNode = lib_common.gUriGen.AddrUri( host, port, proto )
		# BEWARE: Normally the LHS node should be a process !!!
		grph.add( ( nodeHost, pc.property_has_socket, socketNode ) )

cgiEnv.OutCgiRdf(grph)
