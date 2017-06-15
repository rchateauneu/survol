#!/usr/bin/python

"""
Socket information
"""

import re
import sys
import psutil
import socket
import rdflib

import lib_common
from lib_properties import pc

def Main():
	cgiEnv = lib_common.CgiEnv()
	socketNam = cgiEnv.GetId()

	grph = cgiEnv.GetGraph()

	# See AddrUri() to understand the syntax of a socket name.
	socketSplit = socketNam.split(':')
	socketAddr = socketSplit[0]

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

	sys.stderr.write("socketAddr=%s socketPort=%d\n"%(socketAddr,socketPort))
	nodeHost = lib_common.gUriGen.HostnameUri(socketAddr)
	socketNode = lib_common.gUriGen.AddrUri(socketAddr, socketPort )

	grph.add( ( nodeHost, pc.property_has_socket, socketNode ) )

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
