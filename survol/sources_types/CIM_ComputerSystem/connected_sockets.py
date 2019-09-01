#!/usr/bin/env python

"""
Connected sockets
This displays the connected sockets from this host to the local machine.
"""

import sys
import re
import socket
import lib_util
import lib_common

from sources_types import CIM_Process
from sources_types import addr as survol_addr

from lib_properties import pc

def Main():

	cgiEnv = lib_common.CgiEnv( )
	hostname = cgiEnv.GetId()

	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	hostAddr = lib_util.GlobalGetHostByName(hostname)

	# hostNode = lib_common.gUriGen.HostnameUri(hostAddr)
	# BEWARE: The rule whether we use the host name or the host IP is not very clear !
	# The IP address would be unambiguous but less clear.
	hostNode = lib_common.gUriGen.HostnameUri(hostname)
	# serverBox = lib_common.RemoteBox(hostAddr)

	# Similar code in "enumerate_sockets.py"
	for proc in CIM_Process.ProcessIter():
		try:
			if lib_common.UselessProc(proc):
				continue

			pid = proc.pid

			# TCP sockets only.
			all_connect = CIM_Process.PsutilProcConnections(proc)

			Main.node_process = None

			def AssociateWithSockets( grph, larray, rarray ):
				if Main.node_process == None:
					Main.node_process = lib_common.gUriGen.PidUri(pid)

					grph.add( ( Main.node_process, pc.property_host, lib_common.nodeMachine ) )
					grph.add( ( Main.node_process, pc.property_pid, lib_common.NodeLiteral(pid) ) )


				lsocketNode = lib_common.gUriGen.AddrUri( larray[0], larray[1] )
				grph.add( ( lsocketNode, pc.property_information, lib_common.NodeLiteral(cnt.status) ) )
				rsocketNode = lib_common.gUriGen.AddrUri( rarray[0], rarray[1] )
				grph.add( ( lsocketNode, pc.property_information, lib_common.NodeLiteral(cnt.status) ) )
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
