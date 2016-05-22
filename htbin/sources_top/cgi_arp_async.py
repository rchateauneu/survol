#!/usr/bin/python

"""
ARP command - Asynchronous DNS lookup
"""

import sys
import re
import socket
import rdflib
import threading
import time

import lib_arp
import lib_common
from lib_properties import pc

# TODO: Add an option to make it asynchronous or synchronous or without DNS.
# Otherwise we must maintain several versions.

# This thread class gets an IP address, does a dns lookup,
# then creates RDF lookup.
# Asynchronous lookups are much faster when there are done in parallel.
class LookupThread(threading.Thread):
	def __init__(self, linSplit, grph, grph_lock):
		self.linSplit = linSplit
		self.grph = grph
		self.grph_lock = grph_lock

		threading.Thread.__init__(self)

	def run(self):

		hstAddr, hostName, aliases = lib_arp.GetArpHostAliases(self.linSplit)

		# Now we create a node in rdflib, and we need a mutex for that.
		with self.grph_lock:
			hostNode = lib_common.gUriGen.HostnameUri( hostName )
			if hstAddr != hostName:
				self.grph.add( ( hostNode, pc.property_information, rdflib.Literal(hstAddr) ) )
			if self.linSplit[1] != "":
				self.grph.add( ( hostNode, lib_common.MakeProp("MAC"), rdflib.Literal(self.linSplit[1]) ) )
			if self.linSplit[2] != "":
				self.grph.add( ( hostNode, lib_common.MakeProp("ARP_type"), rdflib.Literal(self.linSplit[2]) ) )
			# TODO: Create network interface class.
			if self.linSplit[3] != "":
				self.grph.add( ( hostNode, lib_common.MakeProp("Interface"), rdflib.Literal(self.linSplit[3]) ) )
		# Some throttling, in case there are thousands of nodes.
		# time.sleep(0.01)

def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = rdflib.Graph()

	grph_lock = threading.Lock()

	lookup_threads = []

	for linSplit in lib_arp.GetArpEntries():
		thr = LookupThread( linSplit, grph, grph_lock )
		thr.start()
		lookup_threads.append( thr )

	lib_common.JoinThreads(lookup_threads)

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()
