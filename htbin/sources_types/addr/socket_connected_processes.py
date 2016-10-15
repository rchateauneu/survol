#!/usr/bin/python

"""
Processes connected to a socket
"""

import re
import sys
import socket
import psutil
import rdflib
import lib_common
from sources_types import CIM_Process
from lib_properties import pc

def Main():
	cgiEnv = lib_common.CgiEnv()
	socketNam = cgiEnv.GetId()

	grph = rdflib.Graph()

	# See AddrUri() to understand the syntax of a socket name.
	socketSplit = socketNam.split(':')
	socketName = socketSplit[0]

	socketAddr = socket.gethostbyname(socketName)

	allIpAddrs = [i[4][0] for i in socket.getaddrinfo(socket.gethostname(), None)]

	# If the address is one of our IP addresses, replace it.
	if socketAddr in allIpAddrs:
		socketAddr = "127.0.0.1"

	# TODO: If the input address is not "127.0.0.1", there is NO POINT doing this !!

	# Maybe the port is given as a string, "ssh" or "telnet".
	# See usage of socket.getservbyport
	socketPortString = socketSplit[1]
	try:
		socketPort = int(socketPortString)
	except ValueError:
		socketPort = socket.getservbyname(socketPortString)


	sys.stderr.write("socketName=%s socketAddr=%s socketPort=%d\n" % ( socketName, socketAddr, socketPort ) )

	# TBH, I do not understand why a local address is sometimes displayed as "192.168.1.83",
	# "127.0.0.1", "0.0.0.0" etc...
	# l[0]=    192.168.1.83 l[1]= 5353 NO END
	# l[0]=             ::1 l[1]= 5353 NO END
	# l[0]=         0.0.0.0 l[1]=59135 NO END
	# l[0]=              :: l[1]=59136 NO END
	# l[0]=    192.168.56.1 l[1]= 5353 NO END
	# l[0]=       127.0.0.1 l[1]= 5354 NO END
	# l[0]=         0.0.0.0 l[1]= 1433 NO END
	# l[0]=              :: l[1]= 1433 NO END
	def IsGoodSocket(xarray):
		try:
			# Compares the port number first because this is faster.
			if xarray[1] != socketPort:
				return False

			# Beware: We may have socketName='192.168.1.83', socketAddr='127.0.0.1'
			# but the list of socket will display '192.168.1.83', at least on Windows.
			addr = xarray[0]

			if addr == socketAddr or addr == socketName:
				return True

			if addr == "0.0.0.0" or addr == "::":
				return socketAddr == "127.0.0.1"
		except IndexError:
			pass

		return False

	for proc in psutil.process_iter():
		node_process = None

		# All sockets connected to this process.
		# all_connect = proc.get_connections('all')
		# all_connect = proc.get_connections()
		all_connect = CIM_Process.PsutilProcConnections(proc,'all')

		for cnt in all_connect:
			( larray, rarray ) = lib_common.SocketToPair(cnt)

			try:
				sys.stderr.write("l[0]=%16s l[1]=%5d r[0]=%16s r[1]=%5d\n"
								 % ( larray[0], larray[1], rarray[0], rarray[1] ) )
			except IndexError:
				sys.stderr.write("l[0]=%16s l[1]=%5d NO END\n"
								 % ( larray[0], larray[1] ) )

			isTheSock = IsGoodSocket(larray) or IsGoodSocket(rarray)

			if isTheSock:
				# Creates the process only if not done before.
				if node_process == None:
					pid = proc.pid
					node_process = lib_common.gUriGen.PidUri(pid)

					# PAS BON: CAR PEUT_ETRE LE PROCESS PARENT EST DANS LA LISTE DES PROCESSES QU ON AJOUTE,
					# DONC C EST PAS CLAIR. FAUT VERIFIER LA RELATION DE PARENTE.
					grph.add( ( node_process, pc.property_host, lib_common.nodeMachine ) )
					grph.add( ( node_process, pc.property_pid, rdflib.Literal(pid) ) )

				# No need to be asynchronous because this is always the same socket.
				lib_common.PsutilAddSocketToGraphOne(node_process,cnt,grph)

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()
