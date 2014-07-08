#!/usr/bin/python

import re
import sys
import psutil
import rdflib

# This creates a RDF document containing all the sockets of the hostname.

import lib_common
from lib_common import pc
from rdflib import URIRef, BNode, Literal

def AddressToNode(ipAddr):
	global grph
	if ipAddr not in AddressToNode.dictAddrs:

		# In case of NAT, we will use a blank node instead of a URIRef.
		# addrNode = BNode()
		addrNode = rdflib.term.URIRef(u'urn://' + ipAddr )

		AddressToNode.dictAddrs[ipAddr] = addrNode
		grph.add( ( addrNode, pc.property_ip_addr, Literal( ipAddr ) ) )
	return AddressToNode.dictAddrs[ipAddr]
AddressToNode.dictAddrs = {}

grph = rdflib.Graph()

for proc in psutil.process_iter():
	try:
		if lib_common.UselessProc(proc):
			continue

		pid = proc.pid

		# node_process = BNode() # a GUID is generated
		node_process = lib_common.PidUri(pid)

		# TCP sockets.
		all_connect = proc.get_connections()
		if all_connect:
			# Trop lourd, ca ne sert a rien, dans la mesure ou les processes
			# ont le meme URI, donc ils DOIVENT etre fusionnes (A verifier).
			# A la limite, ca pourrait etre un attribut.
			# grph.add( ( node_process, pc.property_pid, Literal(pid) ) )

			# Not sure this is the best plmace to add this edge.
			grph.add( ( node_process, pc.property_host, lib_common.nodeMachine ) )
			for connect in all_connect:
				# sys.stdout.write('    ')
				if( ( connect.family == 2 )
				and ( connect.type == 1 )
				and ( connect.status == 'ESTABLISHED' )
				):
					lsocketNode = lib_common.AddrUri( connect.laddr[0], connect.laddr[1] )

					rsocketNode = lib_common.AddrUri( connect.raddr[0], connect.laddr[1] )

					# Il faudrait plutot une relation commutative.
					#dummy_socket_pair = BNode()
					#grph.add( ( dummy_socket_pair, pc.property_socket_end, lsocketNode ) )
					#grph.add( ( dummy_socket_pair, pc.property_socket_end, rsocketNode ) )
					grph.add( ( lsocketNode, pc.property_socket_end, rsocketNode ) )

					grph.add( ( node_process, pc.property_has_socket_end, lsocketNode ) )

	except psutil._error.AccessDenied:
		pass
	except psutil._error.NoSuchProcess:
		pass
	except:
		print "Unexpected error:", sys.exc_info()[0]
		raise


lib_common.OutCgiRdf(grph)


