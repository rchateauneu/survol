#!/usr/bin/python

import re
import sys
import socket
import psutil
import rdflib
import lib_common
import lib_entities.lib_entity_CIM_Process as lib_entity_CIM_Process
from lib_properties import pc

def Main():
	cgiEnv = lib_common.CgiEnv("Processes connected to a socket")
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

	sys.stderr.write("socketName=%s socketAddr=%s\n" % ( socketName, socketAddr ) )

	# TODO: If the input address is not "127.0.0.1", there is NO POINT doing this !!

	# Maybe the port is given as a string, "ssh" or "telnet".
	# See usage of socket.getservbyport
	socketPortString = socketSplit[1]
	try:
		socketPort = int(socketPortString)
	except ValueError:
		socketPort = socket.getservbyname(socketPortString)

	for proc in psutil.process_iter():
		node_process = None

		# All sockets connected to this process.
		# all_connect = proc.get_connections('all')
		# all_connect = proc.get_connections()
		all_connect = lib_entity_CIM_Process.PsutilProcConnections(proc,'all')

		for cnt in all_connect:
			( larray, rarray ) = lib_common.SocketToPair(cnt)

			isTheSock = False

			# Compares the port number first because this is faster.
			try:
				isTheSock = larray[1] == socketPort and larray[0] == socketAddr
			except IndexError:
				pass

			if not isTheSock:
				try:
					isTheSock = rarray[1] == socketPort and rarray[0] == socketAddr
				except IndexError:
					pass

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
