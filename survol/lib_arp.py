#!/usr/bin/python

import sys
import re
import subprocess
import socket
import lib_util
import lib_common

# arp -a
#D:\build\IRGCMP\Other\Scripts\MRXFeed>arp -a
#
#Interface: 10.102.235.173 --- 0xb
#  Internet Address      Physical Address      Type
#  10.102.235.245        9c-93-4e-32-c6-df     dynamic
#  10.102.235.255        ff-ff-ff-ff-ff-ff     static
#  239.192.101.76        01-00-5e-40-65-4c     static
#  255.255.255.255       ff-ff-ff-ff-ff-ff     static
#
# TODO: Maybe there is one output per interface.
def GetArpEntriesWindows():
	arp_cmd = [ "arp", "-a" ]

	arp_pipe = subprocess.Popen(arp_cmd, bufsize=100000, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

	( arp_last_output, arp_err ) = arp_pipe.communicate()

	# TODO/ Should be a generator !
	# Converts to string for Python3.
	asstr = arp_last_output.decode("utf-8")
	lines = asstr.split('\n')

	for lin in lines:
		# Maybe should check if other interfaces ??
		# Maybe should create the entity "network interface",
		# instead of this confusion between machines and addresses.

		# ['255.255.255.255', 'ff-ff-ff-ff-ff-ff', 'static', '\\r']
		linSplit = re.findall(r"[^ ]+",lin)

		# sys.stderr.write("GetArpEntriesWindows Split=%s\n"%str(linSplit))

		# Probably not the best test.
		if len(linSplit) != 4:
			continue

		if linSplit[0] == "Interface:":
			continue

		# Network interface.
		linSplit.append("")

		yield( linSplit )

# /sbin/arp -an
# ? (192.168.1.10) at f0:82:61:38:20:5d [ether] on wlp8s4
# ? (192.168.1.88) at <incomplete> on wlp8s4
# ? (192.168.1.17) at 54:be:f7:91:34:0d [ether] on wlp8s4
# ? (192.168.1.83) at <incomplete> on wlp8s4
# ? (192.168.1.11) at f0:cb:a1:61:c7:23 [ether] on wlp8s4
def GetArpEntriesLinux():
	arp_cmd = [ "/sbin/arp", "-an" ]

	arp_pipe = subprocess.Popen(arp_cmd, bufsize=100000, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

	( arp_last_output, arp_err ) = arp_pipe.communicate()

	# TODO/ Should be a generator !
	# Converts to string for Python3.
	asstr = arp_last_output.decode("utf-8")
	lines = asstr.split('\n')

	for lin in lines:
		tmpSplit = re.findall(r"[^ ]+",lin)

		if len(tmpSplit) < 4:
			continue

		if tmpSplit[4] == "on":
			linSplit = [ tmpSplit[1][1:-1], tmpSplit[3], "", tmpSplit[5] ]
		elif tmpSplit[5] == "on":
			linSplit = [ tmpSplit[1][1:-1], tmpSplit[3], "", tmpSplit[6] ]
		else:
			continue

		if linSplit[1] == "<incomplete>":
			linSplit[1] = ""

		sys.stderr.write("Split=%s\n"%str(linSplit))

		yield( linSplit )

def GetArpEntries():
	if lib_util.isPlatformWindows:
		return GetArpEntriesWindows()
	if lib_util.isPlatformLinux:
		return GetArpEntriesLinux()

	lib_common.ErrorMessageHtml("Undefined platform:"+sys.platform)



def GetArpHostAliases(linSplit):
	hstAddr = linSplit[0]
	try:
		hostName, aliases, _ = socket.gethostbyaddr(hstAddr)
	except socket.herror:
		hostName = hstAddr
		aliases = []

	return (hstAddr, hostName, aliases)

