#!/usr/bin/env python

"""
Connected sockets
This displays the connected sockets from this host to the local machine.
"""

import sys
import re
import socket
import psutil

import lib_uris
import lib_util
import lib_common
from sources_types import addr as survol_addr
from lib_properties import pc

def Main():

    cgiEnv = lib_common.ScriptEnvironment( )
    hostname = cgiEnv.GetId()

    cgiEnv = lib_common.ScriptEnvironment()

    grph = cgiEnv.GetGraph()

    host_addr = lib_util.GlobalGetHostByName(hostname)

    # BEWARE: The rule whether we use the host name or the host IP is not very clear !
    # The IP address would be unambiguous but less clear.
    host_node = lib_uris.gUriGen.HostnameUri(hostname)

    # Similar code in "enumerate_sockets.py"
    for proc in psutil.process_iter():
        try:
            pid = proc.pid

            # TCP sockets only.
            all_connect = CIM_Process.PsutilProcConnections(proc)

            Main.node_process = None

            def associate_with_sockets(grph, larray, rarray):
                if Main.node_process == None:
                    Main.node_process = lib_uris.gUriGen.PidUri(pid)

                    grph.add((Main.node_process, pc.property_host, lib_common.nodeMachine))
                    grph.add((Main.node_process, pc.property_pid, lib_util.NodeLiteral(pid)))

                lsocket_node = lib_uris.gUriGen.AddrUri(larray[0], larray[1])
                grph.add((lsocket_node, pc.property_information, lib_util.NodeLiteral(cnt.status)))
                rsocket_node = lib_uris.gUriGen.AddrUri(rarray[0], rarray[1])
                grph.add((lsocket_node, pc.property_information, lib_util.NodeLiteral(cnt.status)))
                grph.add((lsocket_node, pc.property_socket_end, rsocket_node))

                grph.add((Main.node_process, pc.property_has_socket, rsocket_node))
                grph.add((host_node, pc.property_has_socket, lsocket_node))

            for cnt in all_connect:
                if((cnt.family == socket.AF_INET)
                and (cnt.type == socket.SOCK_STREAM)
                and (cnt.status == 'ESTABLISHED')
                ):
                    larray, rarray = cnt.laddr, cnt.raddr

                    if host_addr == larray[0]:
                        associate_with_sockets(grph, larray, rarray)
                    elif host_addr == rarray[0]:
                            associate_with_sockets(grph, rarray, larray)
        except:
            pass

    cgiEnv.OutCgiRdf("LAYOUT_SPLINE")


if __name__ == '__main__':
    Main()
