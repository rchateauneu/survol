#!/usr/bin/python

"""
Nmap master browsers discovery

Discovers master browsers and their managed domains.
"""

import re
import sys
import socket
import xml.dom.minidom
import lib_util
import lib_common
from lib_properties import pc

# https://nmap.org/nsedoc/scripts/broadcast-netbios-master-browser.html
#
# Starting Nmap 7.12 ( https://nmap.org ) at 2017-11-30 07:54 GMT
# Pre-scan script results:
# | broadcast-netbios-master-browser:
# | ip            server           domain
# |_192.168.0.15  WDMYCLOUDMIRROR  WORKGROUP
# WARNING: No targets were specified, so 0 hosts scanned.
# Nmap done: 0 IP addresses (0 hosts up) scanned in 4.32 seconds
#



def Main():
	cgiEnv = lib_common.CgiEnv()

	args = ["nmap", '-oX', '-', '--script', "broadcast-netbios-master-browser", ]

	# The returned IP address is wrong when launched from a Windows machine where the DB is running.
	p = lib_common.SubProcPOpen(args)

	grph = cgiEnv.GetGraph()

	(nmap_last_output, nmap_err) = p.communicate()

	dom = xml.dom.minidom.parseString(nmap_last_output)

	# <script id="broadcast-netbios-master-browser" output="..."/>

	for aScript in dom.getElementsByTagName('script'):
		# output="&#xa;ip server domain&#xa;192.168.0.15  WDMYCLOUDMIRROR  WORKGROUP&#xa;"
		anOutput = aScript.getAttributeNode('output').value.strip()
		sys.stderr.write("anOutput=%s\n"%str(anOutput))
		arrSplit = [ aWrd.strip() for aWrd in anOutput.split("\n") ]

		sys.stderr.write("arrSplit=%s\n"%str(arrSplit))

		theMachFull = arrSplit[1].strip()
		sys.stderr.write("theMachFull=%s\n"%str(theMachFull))
		machSplit = re.split( "[\t ]+", theMachFull )
		sys.stderr.write("machSplit=%s\n"%str(machSplit))
		machIp = machSplit[0].strip()
		machNam = machSplit[1].strip()
		nameDomain = machSplit[2].strip()

		nodeHost = lib_common.gUriGen.HostnameUri( machNam )
		grph.add( ( nodeHost, lib_common.MakeProp("IP address"), lib_common.NodeLiteral( machIp ) ) )
		grph.add( ( nodeHost, lib_common.MakeProp("Domain"), lib_common.NodeLiteral( nameDomain ) ) )
		grph.add( ( nodeHost, pc.property_information, lib_common.NodeLiteral( arrSplit[0] ) ) )

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
