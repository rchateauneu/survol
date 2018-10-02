#!/usr/bin/python

"""
Socket information
"""

import re
import sys
import socket

import lib_common
from lib_properties import pc

def Main():
	cgiEnv = lib_common.CgiEnv()
	socketNam = cgiEnv.GetId()

	grph = cgiEnv.GetGraph()

	# See AddrUri() to understand the syntax of a socket name.
	socketSplit = socketNam.split(':')
	socketAddr = socketSplit[0]

	try:
		socketHost = socket.gethostbyaddr(socketAddr)[0]
	except:
		socketHost = socketAddr

	# Maybe the port is given as a string, "ssh" or "telnet".
	# See usage of socket.getservbyport
	socketPortString = socketSplit[1]
	try:
		socketPort = int(socketPortString)
	except ValueError:
		socketPort = socket.getservbyname(socketPortString)

	# TCP is the default protocol.
	try:
		socketTransport = socketSplit[2]
	except IndexError:
		socketTransport = "tcp"

	DEBUG("socketAddr=%s socketPort=%d",socketAddr,socketPort)
	# It uses the host name for the machine but an IP address for the socket.
	nodeHost = lib_common.gUriGen.HostnameUri(socketHost)
	socketNode = lib_common.gUriGen.AddrUri(socketAddr, socketPort )

	grph.add( ( nodeHost, pc.property_has_socket, socketNode ) )

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
