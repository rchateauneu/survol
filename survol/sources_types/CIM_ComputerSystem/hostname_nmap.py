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

from sources_types import addr as survol_addr

def Main():
	paramkeyPortsRange = "Ports Range"

	cgiEnv = lib_common.CgiEnv(
			{ paramkeyPortsRange : "22-443" } )
	hostname = cgiEnv.GetId()
	nodeHost = lib_common.gUriGen.HostnameUri( hostname )

	# This is just a first experimentation with nmap.
	# Ideally, the port range could be changed in edit mode of this script.
	portsRange = cgiEnv.GetParameters( paramkeyPortsRange )
	args = ['nmap', '-oX', '-', hostname, '-p', portsRange ]

	# NOTE: This is completely similar to the script in the sources directory.
	try:
		p = lib_common.SubProcPOpen(args)
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Cannot find nmap:"+str(exc))

	grph = cgiEnv.GetGraph()

	( nmap_last_output, nmap_err) = p.communicate()

	try:
		dom = xml.dom.minidom.parseString(nmap_last_output)
	except xml.parsers.expat.ExpatError:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("XML error:"+nmap_last_output+", caught:" + str(exc) )

	for dhost in dom.getElementsByTagName('host'):
		nodeIP = dhost.getElementsByTagName('address')[0].getAttributeNode('addr').value
		# print("host="+host)
		# Probleme: Ni l'adresse IP ni le nom ne sont uniques pour une machines.
		# En realite une machine peut avoir plusieurs interfaces reseau, et chaque
		# interface reseau peut avoir plusieurs noms. Mais une machine peut donner
		# le meme nom a plusieurs adresses IP.
		# nodeIP = lib_common.gUriGen.HostnameUri( host )

		grph.add( ( nodeHost, lib_common.MakeProp("IP"), lib_common.NodeLiteral( nodeIP ) ) )
		# PAS EXACTEMENT nodeHost: Ca affiche l IP (192.168.1.76) mais il faudrait "Titi"
		### nodeHost = lib_common.gUriGen.HostnameUri(hostname)
		# Et donc ca duplique le node.

		for dhostname in dhost.getElementsByTagName('hostname'):
			sub_hostnam = dhostname.getAttributeNode('name').value

			# grph.add( ( nodeHost, pc.property_hostname, lib_common.NodeLiteral( sub_hostnam ) ) )
			# It should be the same as the main hostname, which is taken as reference to avoid ambiguities.
			grph.add( ( nodeHost, lib_common.MakeProp("Hostname"), lib_common.NodeLiteral( sub_hostnam ) ) )

		for dport in dhost.getElementsByTagName('port'):
			proto = dport.getAttributeNode('protocol').value

			# port number converted as integer
			port = int(dport.getAttributeNode('portid').value)
			socketNode = lib_common.gUriGen.AddrUri( hostname, port, proto )
			survol_addr.DecorateSocketNode(grph, socketNode, hostname, port, proto)

			state = dport.getElementsByTagName('state')[0].getAttributeNode('state').value
			grph.add( ( socketNode, lib_common.MakeProp("State"), lib_common.NodeLiteral(state) ) )
			
			reason = dport.getElementsByTagName('state')[0].getAttributeNode('reason').value
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

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
