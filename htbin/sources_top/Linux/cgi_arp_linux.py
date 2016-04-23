#!/usr/bin/python

"""
ARP command for Linux
"""

# TODO: Maybe there is one output per interface.
import sys
import re
import socket
import rdflib
import socket
import subprocess

import lib_common
from lib_properties import pc

def Main():
	cgiEnv = lib_common.CgiEnv("ARP command for Linux")

	if not 'linux' in sys.platform:
		lib_common.ErrorMessageHtml("Linux only")

	grph = rdflib.Graph()

	arp_cmd = [ "/sbin/arp", "-a" ]

	arp_pipe = subprocess.Popen(arp_cmd, bufsize=100000, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

	( arp_last_output, arp_err ) = arp_pipe.communicate()

	# Converts to string for Python3.
	asstr = arp_last_output.decode("utf-8")

	lines = asstr.split('\n')

	lookup_threads = []

	cnt = 0

	for lin in lines:
		sys.stderr.write("Lin=%s\n"%lin)
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
		grph.add( ( hostNode, pc.property_information, rdflib.Literal(mtch_arp.group(2)) ) )
		grph.add( ( hostNode, pc.property_information, rdflib.Literal(mtch_arp.group(3)) ) )

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()
