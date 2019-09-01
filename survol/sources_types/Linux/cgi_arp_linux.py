#!/usr/bin/env python

"""
ARP command for Linux
"""

# TODO: Maybe there is one output per interface.
import sys
import re
import socket
import socket
import lib_util
import lib_common
from lib_properties import pc

def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	arp_cmd = [ "/sbin/arp", "-a" ]

	arp_pipe = lib_common.SubProcPOpen(arp_cmd)

	( arp_last_output, arp_err ) = arp_pipe.communicate()

	# Converts to string for Python3.
	asstr = arp_last_output.decode("utf-8")

	lines = asstr.split('\n')

	lookup_threads = []

	cnt = 0

	for lin in lines:
		DEBUG("Lin=%s",lin)
		#print("se="+str(seenHyphens)+" Lin=("+lin+")")

		# Maybe should check if other interfaces ??
		# Maybe should create the entity "network interface",
		# instead of this confusion between machines and addresses.

		# BThomehub.home (192.168.1.254) at 18:62:2C:63:98:6A [ether] on eth0
		mtch_arp = re.match( "([^ ]+) \(([^)]+)\) at ([^ ]+) .*", lin )

		if not mtch_arp:
			continue

		hostName = mtch_arp.group(1)
		hostNode = lib_common.gUriGen.HostnameUri( hostName )
		grph.add( ( hostNode, pc.property_information, lib_common.NodeLiteral(mtch_arp.group(2)) ) )
		grph.add( ( hostNode, pc.property_information, lib_common.NodeLiteral(mtch_arp.group(3)) ) )

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
