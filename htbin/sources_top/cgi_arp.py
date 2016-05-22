#!/usr/bin/python

"""
ARP Command
"""

import sys
import re
import rdflib

import lib_common
import lib_arp
from lib_properties import pc


def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = rdflib.Graph()

	for linSplit in lib_arp.GetArpEntries():
		hstAddr, hostName, aliases = lib_arp.GetArpHostAliases(linSplit)

		hostNode = lib_common.gUriGen.HostnameUri( hostName )
		if hstAddr != hostName:
			grph.add( ( hostNode, pc.property_information, rdflib.Literal(hstAddr) ) )
		grph.add( ( hostNode, pc.property_information, rdflib.Literal(linSplit[1]) ) )
		grph.add( ( hostNode, pc.property_information, rdflib.Literal(linSplit[2]) ) )

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()
