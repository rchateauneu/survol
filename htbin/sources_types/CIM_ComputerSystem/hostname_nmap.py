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
hostname = cgiEnv.GetId()

# This is just a first experimentation with nmap.
# Ideally, the port range could be changed in edit mode of this script.
portsRange = cgiEnv.GetParameters( paramkeyPortsRange )
args = ['nmap', '-oX', '-', hostname, '-p', portsRange ]

# NOTE: This is completely similar to the script in the sources directory.
try:
	p = subprocess.Popen(args, bufsize=100000, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
except Exception:
	exc = sys.exc_info()[1]
	lib_common.ErrorMessageHtml("Cannot find nmap:"+str(exc))
	
grph = rdflib.Graph()

( nmap_last_output, nmap_err) = p.communicate()

try:
	dom = xml.dom.minidom.parseString(nmap_last_output)
except xml.parsers.expat.ExpatError:
	exc = sys.exc_info()[1]
	lib_common.ErrorMessageHtml("XML error:"+nmap_last_output+", caught:" + str(exc) )

for dhost in dom.getElementsByTagName('host'):
	host = dhost.getElementsByTagName('address')[0].getAttributeNode('addr').value
	# print("host="+host)
	# Probleme: Ni l'adresse IP ni le nom ne sont uniques pour une machines.
	# En realite une machine peut avoir plusieurs interfaces reseau, et chaque
	# interface reseau peut avoir plusieurs noms. Mais une machine peut donner
	# le meme nom a plusieurs adresses IP.
	nodeHost = lib_common.gUriGen.HostnameUri( host )
	for dhostname in dhost.getElementsByTagName('hostname'):
		hostnam = dhostname.getAttributeNode('name').value
		grph.add( ( nodeHost, pc.property_hostname, rdflib.Literal( hostnam ) ) )

	for dport in dhost.getElementsByTagName('port'):
		proto = dport.getAttributeNode('protocol').value
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
