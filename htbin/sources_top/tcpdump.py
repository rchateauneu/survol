#!/usr/bin/python

# It works also for WindDump.exe, on Windows.

import os
import re
import sys
import time
import rdflib
import lib_util
import lib_common
from lib_properties import pc

import lib_webserv

# TODO: Uses classes instead of functions.

################################################################################

# This runs in the HTTP server and uses the data from the queue.
# This reads a record from the queue and builds a RDF relation with it.
def TcpDumpDeserialize( log_strm, grph, tuple):
	if tuple[0] == 'IP':
		# TODO: Precompile the regular expression, but this is buggy in Python 2.5
		addrRegex = r'(.*)\.([^.]*)'

		# Maybe we should have a commutative relation?
		lMatchAddr = re.match( addrRegex, tuple[1], re.M|re.I)
		if not lMatchAddr:
			return
		lsocketNode = lib_common.gUriGen.AddrUri( lMatchAddr.group(1), int(lMatchAddr.group(2)) )

		rMatchAddr = re.match( addrRegex, tuple[2], re.M|re.I)
		if not rMatchAddr:
			return
		rsocketNode = lib_common.gUriGen.AddrUri( rMatchAddr.group(1), int(rMatchAddr.group(2)) )

		grph.add( ( lsocketNode, pc.property_socket_end, rsocketNode ) )

################################################################################

# Runs in the subprocess of the HTTP server and parses the output of "tcpdump"
# or "WinDump.exe" if on Windows.
def TcpDumpEnqueue(theQ, line):
	spl = line.split(' ')

	# 22:39:56.713245 IP BThomehub.home.domain > Unknown-00-18-e7-08-02-81.home.47676: 52407* 1/0/0 (87)
	if spl[1] == 'IP':
		theQ.put( ( 'IP', spl[2], spl[4][:-1] ) )
	# 22:39:56.319537 STP 802.1d, Config, Flags [none], bridge-id 8000.18:62:2c:63:98:6b.8000, length 43
	elif spl[1] == 'STP':
		# Spanning bridge protocol.
		theQ.put( ( 'STP', spl[7] ) )
	elif spl[1] == 'arp':
		# 22:14:28.425307 arp reply BThomehub.home is-at 18:62:2c:63:98:6a (oui Unknown)
		if spl[2] == 'reply':
			theQ.put( ('ArpReply' , spl[3], spl[5] ) )
		# 22:14:07.435267 arp who-has pcvero.home tell BThomehub.home
		elif spl[2] == 'who-has':
			theQ.put( ('ArpWho' , spl[3], spl[5] ) )

def GetTcmpDumpCommand():
	if lib_util.isPlatformWindows:
		return "WinDump"
	else:
		# Option -n so no conversion of addresses and port numbers.
		return "sudo tcpdump -n"

# This runs tcpdump, parses output data from it, then written in the queue.
# The communication queue is made of pairs of sockets.
# The entity id should be the default value and is not relevant.
def TcpDumpEngine(sharedTupleQueue,entityId):
	tmpFil = lib_common.TmpFile("TcpDump","log")
	filNam = tmpFil.Name
	fil = open(filNam,"w")

	tcpdump_cmd = GetTcmpDumpCommand()
	fil.write( "TCPcommand=%s\n" % ( tcpdump_cmd ) )
	fil.flush()
	cnt = 0
	for lin in os.popen(tcpdump_cmd):
		sys.stderr.write("cnt=%d:%s\n" % ( cnt, lin ) )
		if lin:
			TcpDumpEnqueue( sharedTupleQueue, lin )
			if cnt % 100 == 0:
				fil.write("cnt=%d:%s" % ( cnt, lin ) )
				fil.flush()
			cnt += 1

	fil.write( "Leaving after %d iterations\n" % ( cnt ) )
	fil.close()

	return "Tcpdump execution end"

################################################################################

if __name__ == '__main__':
	img = "http://sectools.org/logos/tcpdump-80x70.png"
	lib_webserv.DoTheJob(TcpDumpEngine,TcpDumpDeserialize,__file__,"Tcpdump display",img)
