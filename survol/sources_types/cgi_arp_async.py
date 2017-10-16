#!/usr/bin/python

"""
ARP command - Asynchronous DNS lookup
"""

import sys
import re
import socket
import threading
import time

import lib_arp
import lib_common
from lib_properties import pc

def GetMacVendor(macAddress):
	"""
		This returns the vendor name of this mac address.
		There is no garantee that this website is reliable, so there is a strict time-out.
		It returns something like: "Hewlett Packard"|"B0:5A:DA"|"11445 Compaq Center Drive,Houston 77070,US"|"B05ADA000000"|"B05ADAFFFFFF"|"US"|"MA-L"
	"""
	urlMac = "https://macvendors.co/api/%s/pipe" % macAddress
	try:
		#sys.stderr.write("urlMac=%s\n"%urlMac)

		import urllib2
		req = urllib2.Request(urlMac)
		req.add_header('User-Agent', "API Browser")
		resp = urllib2.urlopen(req)
		content = resp.readlines()[0]

		#sys.stderr.write("content=%s\n"%content)
		#sys.stderr.write("content=%s\n"%str(type(content)))
		splitMac = content.split("|")
		#sys.stderr.write("splitMac[0]=%s\n"%splitMac[0])
		return splitMac[0]
	except:
		exc = sys.exc_info()[1]
		#sys.stderr.write("Caught %s\n"%str(exc))
		# Any error returns a none strng: Thisinformation is not that important.
		return None

# TODO: Add an option to make it asynchronous or synchronous or without DNS.
# Otherwise we must maintain several versions.

class LookupThread(threading.Thread):
	"""
		This thread class gets an IP address, does a dns lookup,
		then creates RDF lookup.
		Asynchronous lookups are much faster when there are done in parallel.
	"""
	def __init__(self, linSplit, grph, grph_lock, map_hostnames_ipcount):
		self.linSplit = linSplit
		self.grph = grph
		self.grph_lock = grph_lock
		self.map_hostnames_ipcount = map_hostnames_ipcount

		threading.Thread.__init__(self)

	def run(self):

		hstAddr, hostName, aliases = lib_arp.GetArpHostAliases(self.linSplit)

		# Now we create a node in rdflib, and we need a mutex for that.
		with self.grph_lock:
			try:
				lstIpAddrs = self.map_hostnames_ipcount[hostName]

				if hstAddr in lstIpAddrs:
					sys.stderr.write("+++++++++++++++ hostName=%s hstAddr=%s AGAIN num=%d\n"%(hostName,hstAddr,len(self.map_hostnames_ipcount)))
					return

				lstIpAddrs.add(hstAddr)
				labelExt = "_%d" % len(lstIpAddrs)
				sys.stderr.write("+++++++++++++++ hostName=%s hstAddr=%s OTHER num=%d\n"%(hostName,hstAddr,len(self.map_hostnames_ipcount)))
			except KeyError:
				sys.stderr.write("+++++++++++++++ hostName=%s hstAddr=%s FIRST num=%d\n"%(hostName,hstAddr,len(self.map_hostnames_ipcount)))
				self.map_hostnames_ipcount[hostName] = {hstAddr}
				labelExt = ""

			hostNode = lib_common.gUriGen.HostnameUri( hostName )
			if hstAddr != hostName:
				self.grph.add( ( hostNode, lib_common.MakeProp("IP address"+labelExt), lib_common.NodeLiteral(hstAddr) ) )

			topDig = hstAddr.split(".")[0]
			if topDig == "224":
				# TODO: Check multicast detection.
				self.grph.add( ( hostNode, pc.property_information, lib_common.NodeLiteral("Multicast") ) )
			else:
				macAddress = self.linSplit[1].upper()
				if macAddress not in ["","FF-FF-FF-FF-FF-FF"]:
					self.grph.add( ( hostNode, lib_common.MakeProp("MAC"+labelExt), lib_common.NodeLiteral(macAddress) ) )
					ncCompany = GetMacVendor(macAddress)
					if ncCompany:
						self.grph.add( ( hostNode, lib_common.MakeProp("Vendor"+labelExt), lib_common.NodeLiteral(ncCompany) ) )

			# static/dynamic
			arpType = self.linSplit[2]
			if arpType != "":
				self.grph.add( ( hostNode, lib_common.MakeProp("ARP_type"), lib_common.NodeLiteral(arpType) ) )

			# TODO: Create network interface class.
			hostItf = self.linSplit[3].split()
			if hostItf:
				self.grph.add( ( hostNode, lib_common.MakeProp("Interface"), lib_common.NodeLiteral(hostItf) ) )

def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	# Several threads can add nodes at the same time.
	grph_lock = threading.Lock()

	map_hostnames_ipcount = dict()

	lookup_threads = []

	for linSplit in lib_arp.GetArpEntries():
		thr = LookupThread( linSplit, grph, grph_lock, map_hostnames_ipcount )
		thr.start()
		lookup_threads.append( thr )

	for thread in lookup_threads:
		# sys.stderr.write('Joining %s\n' % thread.getName())
		thread.join()

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
