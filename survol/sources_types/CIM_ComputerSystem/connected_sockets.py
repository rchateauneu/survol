#!/usr/bin/env python

"""
Connected sockets
This displays the connected sockets from this host to the local machine.
"""

import sys
import re
import socket
import psutil
import lib_util
import lib_common

from sources_types import addr as survol_addr

from lib_properties import pc

def Main():

	cgiEnv = lib_common.CgiEnv( )
	hostname = cgiEnv.GetId()

	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	hostAddr = lib_util.GlobalGetHostByName(hostname)

	# BEWARE: The rule whether we use the host name or the host IP is not very clear !
	# The IP address would be unambiguous but less clear.
	hostNode = lib_common.gUriGen.HostnameUri(hostname)

	# Similar code in "enumerate_sockets.py"
	for proc in psutil.process_iter():
		try:
			if lib_common.is_useless_process(proc):
				continue

			pid = proc.pid

			# TCP sockets only.
			all_connect = CIM_Process.PsutilProcConnections(proc)

			Main.node_process = None

			def AssociateWithSockets( grph, larray, rarray ):
				if Main.node_process == None:
					Main.node_process = lib_common.gUriGen.PidUri(pid)

					grph.add( ( Main.node_process, pc.property_host, lib_common.nodeMachine ) )
					grph.add( ( Main.node_process, pc.property_pid, lib_util.NodeLiteral(pid) ) )


				lsocketNode = lib_common.gUriGen.AddrUri( larray[0], larray[1] )
				grph.add( ( lsocketNode, pc.property_information, lib_util.NodeLiteral(cnt.status) ) )
				rsocketNode = lib_common.gUriGen.AddrUri( rarray[0], rarray[1] )
				grph.add( ( lsocketNode, pc.property_information, lib_util.NodeLiteral(cnt.status) ) )
				grph.add( ( lsocketNode, pc.property_socket_end, rsocketNode ) )

				grph.add( ( Main.node_process, pc.property_has_socket, rsocketNode ) )
				grph.add( ( hostNode, pc.property_has_socket, lsocketNode ) )

			for cnt in all_connect:
				if( ( cnt.family == socket.AF_INET )
				and ( cnt.type == socket.SOCK_STREAM )
				and ( cnt.status == 'ESTABLISHED' )
				):
					( larray, rarray ) = survol_addr.SocketToPair(cnt)

					if hostAddr == larray[0]:
						AssociateWithSockets( grph, larray, rarray )
					elif hostAddr == rarray[0]:
							AssociateWithSockets( grph, rarray, larray )


		except:
			pass

	cgiEnv.OutCgiRdf("LAYOUT_SPLINE")


if __name__ == '__main__':
	Main()
