#!/usr/bin/python

import sys
import re
import socket
import rdflib
import threading
import time

import lib_arp
import lib_common
from lib_properties import pc

cgiEnv = lib_common.CgiEnv("ARP command - Asynchronous DNS lookup")

grph_lock = threading.Lock()


# TODO: Add an option to make it asynchronous or synchronous or without DNS.
# Otherwise we must maintain several versions.

# This thread class gets an IP address, does a dns lookup,
# then creates RDF lookup.
# Asynchronous lookups are much faster when there are done in parallel.
class LookupThread(threading.Thread):
	def __init__(self, linSplit):
		self.linSplit = linSplit

		threading.Thread.__init__(self)

	def run(self):
		global grph
		global grph_lock

		hstAddr, hostName, aliases = lib_arp.GetArpHostAliases(self.linSplit)

		# Now we create a node in rdflib, and we need a mutex for that.
		with grph_lock:
			hostNode = lib_common.gUriGen.HostnameUri( hostName )
			if hstAddr != hostName:
				grph.add( ( hostNode, pc.property_information, rdflib.Literal(hstAddr) ) )
			if linSplit[1] != "":
				grph.add( ( hostNode, lib_common.MakeProp("MAC"), rdflib.Literal(linSplit[1]) ) )
			if linSplit[2] != "":
				grph.add( ( hostNode, lib_common.MakeProp("ARP_type"), rdflib.Literal(linSplit[2]) ) )
			# TODO: Create network interface class.
			if linSplit[3] != "":
				grph.add( ( hostNode, lib_common.MakeProp("Interface"), rdflib.Literal(linSplit[3]) ) )
		# Some throttling, in case there are thousands of nodes.
		# time.sleep(0.01)

grph = rdflib.Graph()

lookup_threads = []

for linSplit in lib_arp.GetArpEntries():
	thr = LookupThread( linSplit )
	thr.start()
	lookup_threads.append( thr )

lib_common.JoinThreads(lookup_threads)

cgiEnv.OutCgiRdf(grph)

