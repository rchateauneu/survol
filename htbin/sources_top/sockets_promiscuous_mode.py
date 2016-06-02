#!/usr/bin/python

"""
Sockets in promiscuous mode
"""

# It works also for WindDump.exe, on Windows.

import os
import re
import sys
import time
import socket
import binascii
import lib_util
import lib_common
from lib_properties import pc
import lib_webserv

Usable = lib_util.UsableAsynchronousSource

################################################################################

# This runs in the HTTP server and uses the data from the queue.
# This reads a record from the queue and builds a RDF relation with it.
def PromiscuousDeserialize( log_strm, grph, tuple):
	if tuple[0] == 6:
		lsocketNode = lib_common.gUriGen.AddrUri( tuple[1], tuple[2] )

		rsocketNode = lib_common.gUriGen.AddrUri( tuple[3], tuple[4] )

		grph.add( ( lsocketNode, pc.property_socket_end, rsocketNode ) )

################################################################################

def DecodePort(pck,offset):
	port = 256 * pck[offset+0] + pck[offset+1]
	return port

def BytesToAddr(pck, offset):
	try:
		ip = "%d.%d.%d.%d" % ( pck[offset+12],pck[offset+13],pck[offset+14],pck[offset+15] )
		addr = socket.gethostbyaddr(ip)[0]
		return addr
	except socket.herror:
		return ""


################################################################################

def ProcessFrame(theQ, receivedPacket):

	protoc = receivedPacket[9]
	# 6 = TCP
	# 17 = UDP
	# 103 = PIM
	if protoc != 6: # TCP
		return

	ihl = receivedPacket[0] % 16
	# Cannot go further.
	if ihl <= 6 :
		return

	sourceAddr = BytesToAddr( receivedPacket, 12 )
	destinationAddr = BytesToAddr( receivedPacket, 16 )

	lenall = len(receivedPacket)
	if lenall >= 24:
		offBase = ihl * 4

		sourcePort = DecodePort(receivedPacket, offBase )
		destinationPort = DecodePort(receivedPacket, offBase + 2)
	else:
		sourcePort = 0
		destinationPort = 0

	theQ.put( ( protoc , sourceAddr, sourcePort, destinationAddr, destinationPort ) )


# The communication queue is made of protocol+addr+port+addr+port.
# The entity id should be the default value and is not relevant.
def PromiscuousEngineWin(sharedTupleQueue,entityId):
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

	# prevent socket from being left in TIME_WAIT state, enabling reuse
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s.bind((lib_util.currentHostname, 0))
	
	# Include IP headers
	s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
	
	s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

	bufferSize=4096
	while True:
		# TODO: Avoid an allocation.
		package=s.recv(bufferSize)
		try:
			ProcessFrame(sharedTupleQueue, package)
		except Exception:
			exc = sys.exc_info()[1]
			errMsg = "Caught:%s" % str(exc)
			break
		# Less data otherwise it is not sustainable.
		time.sleep(0.2)
	
	# disable promiscuous mode
	s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

	return errMsg


################################################################################

def PromiscuousEngineLinux(sharedTupleQueue,entityId):
	rawSocket=socket.socket(socket.PF_PACKET,socket.SOCK_RAW,socket.htons(0x0800))
	
	while True:
		#ifconfig eth0 promisc up
		receivedPacket=rawSocket.recv(2048)
	
		#Ethernet Header...
		ethernetHeader=receivedPacket[0:14]
		ethrheader=struct.unpack("!6s6s2s",ethernetHeader)
		destinationIP= binascii.hexlify(ethrheader[0])
		sourceIP= binascii.hexlify(ethrheader[1])
		protoc = binascii.hexlify(ethrheader[2])
	
		#IP Header... 
		ipHeader=receivedPacket[14:34]
		ipHdr=struct.unpack("!12s4s4s",ipHeader)
		destinationIP=socket.inet_ntoa(ipHdr[2])
		sourceIP=socket.inet_ntoa(ipHdr[1])
	
		#TCP Header...
		tcpHeader=receivedPacket[34:54]
		tcpHdr=struct.unpack("!2s2s16s",tcpHeader)
		try:
			sourcePort = DecodePort(tcpHdr[0],0)
	
			destinationPort=DecodePort(tcpHdr[1],0)
		except Exception:
			exc = sys.exc_info()[1]
			print("Caught:%s" % str(exc) )
		time.sleep(0.2)

		sharedTupleQueue.put( ( protoc , sourceIP, sourcePort, destinationIP, destinationPort ) )
	


################################################################################

def PromiscuousEngine(sharedTupleQueue,entityId):
	if lib_util.isPlatformWindows:
		PromiscuousEngineWin(sharedTupleQueue,entityId)
	else:
		PromiscuousEngineLinux(sharedTupleQueue,entityId)

################################################################################

if __name__ == '__main__':
	lib_webserv.DoTheJob(PromiscuousEngine,PromiscuousDeserialize,__file__,"Sockets in promiscuous mode")
