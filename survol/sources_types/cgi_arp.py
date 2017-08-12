#!/usr/bin/python

"""
ARP Command
"""

import sys
import re

import lib_common
import lib_arp
from lib_properties import pc


def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	for linSplit in lib_arp.GetArpEntries():
		hstAddr, hostName, aliases = lib_arp.GetArpHostAliases(linSplit)

		hostNode = lib_common.gUriGen.HostnameUri( hostName )
		if hstAddr != hostName:
			grph.add( ( hostNode, pc.property_information, lib_common.NodeLiteral(hstAddr) ) )
		grph.add( ( hostNode, pc.property_information, lib_common.NodeLiteral(linSplit[1]) ) )
		grph.add( ( hostNode, pc.property_information, lib_common.NodeLiteral(linSplit[2]) ) )

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
