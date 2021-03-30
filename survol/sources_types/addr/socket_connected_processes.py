#!/usr/bin/env python

"""
Processes connected to socket
"""

import re
import sys
import socket
import psutil
import logging

import lib_uris
import lib_util
import lib_common
from sources_types import CIM_Process
from sources_types import addr as survol_addr

from lib_properties import pc


def Main():
    cgiEnv = lib_common.ScriptEnvironment()
    socket_nam = cgiEnv.GetId()

    grph = cgiEnv.GetGraph()

    # See AddrUri() to understand the syntax of a socket name.
    socket_split = socket_nam.split(':')
    socket_name = socket_split[0]

    socket_addr = lib_util.GlobalGetHostByName(socket_name)

    all_ip_addrs = [i[4][0] for i in socket.getaddrinfo(socket.gethostname(), None)]

    # If the address is one of our IP addresses, replace it.
    if socket_addr in all_ip_addrs:
        socket_addr = "127.0.0.1"

    # TODO: If the input address is not "127.0.0.1", there is NO POINT doing this !!

    # Maybe the port is given as a string, "ssh" or "telnet".
    # See usage of socket.getservbyport
    socket_port_string = socket_split[1]
    try:
        socket_port = int(socket_port_string)
    except ValueError:
        socket_port = socket.getservbyname(socket_port_string)

    logging.debug("socket_name=%s socket_addr=%s socket_port=%d", socket_name, socket_addr, socket_port)

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
    def is_good_socket(xarray):
        try:
            # Compares the port number first because this is faster.
            if xarray[1] != socket_port:
                return False

            # Beware: We may have socket_name='192.168.1.83', socket_addr='127.0.0.1'
            # but the list of socket will display '192.168.1.83', at least on Windows.
            addr = xarray[0]

            if addr == socket_addr or addr == socket_name:
                return True

            # "::1" is equivalent to 127.0.0.1 for IPV6.
            if addr == "0.0.0.0" or addr == "::" or addr == "::1":
                return socket_addr == "127.0.0.1"
        except IndexError:
            pass

        return False

    for proc in psutil.process_iter():
        node_process = None

        # All sockets connected to this process.
        all_connect = CIM_Process.PsutilProcConnections(proc, 'all')

        for cnt in all_connect:
            # pconn(fd=13, family=<AddressFamily.AF_INET: 2>, type=<SocketKind.SOCK_STREAM: 1>, laddr=('127.0.0.1', 8000), raddr=(), status='LISTEN')
            # The socket can be empty.            
            # pconn(fd=15, family=<AddressFamily.AF_UNIX: 1>, type=2, laddr='/run/user/1001/systemd/notify', raddr=None, status='NONE')
            larray, rarray = cnt.laddr, cnt.raddr
            if not larray or not rarray:
                logging.debug("Empty socket. Continue.")
                continue

            try:
                logging.debug("l[0]=%16s l[1]=%5d r[0]=%16s r[1]=%5d", larray[0], larray[1], rarray[0], rarray[1])
            except IndexError:
                try:
                    logging.debug("l[0]=%16s l[1]=%5d NO END", larray[0], larray[1])
                except IndexError:
                    logging.debug("No socket")

            is_the_sock = is_good_socket(larray) or is_good_socket(rarray)

            if is_the_sock:
                # Creates the process only if not done before.
                if node_process == None:
                    pid = proc.pid
                    node_process = lib_uris.gUriGen.PidUri(pid)

                    grph.add((node_process, pc.property_host, lib_common.nodeMachine))
                    grph.add((node_process, pc.property_pid, lib_util.NodeLiteral(pid)))

                # No need to be asynchronous because this is always the same socket.
                survol_addr.PsutilAddSocketToGraphOne(node_process, cnt, grph)

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
