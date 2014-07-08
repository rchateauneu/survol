#!/usr/bin/python

# L idee st qu'on a un process qui fait tourner tcpdump et en tire une carte des sockets
# Probleme: Comment entrer des parametres de filtrage?
# De meme que pour pslist, un seul par reseau.

import lib_common

import os
import re
import sys
import time
import rdflib
from rdflib import Literal
from lib_common import pc

import lib_webserv

################################################################################

# This runs in the HTTP server and uses the data from the queue.
# This reads a record from the queue and builds a RDF relation with it.
def TcpDumpDeserialize(grph, tuple):
	if tuple[0] == 'IP':
		# TODO: Precompile the regular expression, but this is buggy in Python 2.5
		addrRegex = r'(.*)\.([^.]*)'

		# Maybe we should have a commutative relation?
		lMatchAddr = re.match( addrRegex, tuple[1], re.M|re.I)
		if not lMatchAddr:
			return
		lsocketNode = lib_common.AddrUri( lMatchAddr.group(1), lMatchAddr.group(2) )

		rMatchAddr = re.match( addrRegex, tuple[2], re.M|re.I)
		if not rMatchAddr:
			return
		rsocketNode = lib_common.AddrUri( rMatchAddr.group(1), rMatchAddr.group(2) )

		grph.add( ( lsocketNode, pc.property_socket_end, rsocketNode ) )

################################################################################

# Runs in the subprocess of the HTTP server and parses the output of "tcpdump".
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


# This runs tcpdump, parses output data from it, then written in the queue.
# The communication queue is made of pairs of sockets.
# The entity id should be the default value and is not relevant.
def TcpDumpEngine(sharedTupleQueue,entityId):
	#print("Filling queue")
	#for i in range(0,10):
	#	time.sleep(0.1)
	#	# RDF serialization needs Unicode strings.
	#	subject = 'sujet_'+str(i)
	#	complement = 'complement_'+str(i)
	#	my_tuple=( 'IP', subject.encode('utf-8'), complement.encode('utf-8'),  )
	#	sharedTupleQueue.put( my_tuple )

	# Option -n so no conversion of addresses and port numbers.
	tcpdump_cmd = "sudo tcpdump -n"
	print("TCPcommand=" + tcpdump_cmd)
	for lin in os.popen(tcpdump_cmd):
		if lin:
			TcpDumpEnqueue( sharedTupleQueue, lin )

################################################################################

# Conventional port number for TCP dump RDF generation.
TcpDumpPort = 12345

if __name__ == '__main__':
	lib_webserv.DoTheJob(TcpDumpEngine,TcpDumpPort,TcpDumpDeserialize,__file__)
