#!/usr/bin/env python

"""
Socket information
"""

import re
import sys
import socket
import logging

import lib_uris
import lib_common
from lib_properties import pc


def Main():
    cgiEnv = lib_common.ScriptEnvironment()
    socket_nam = cgiEnv.GetId()

    grph = cgiEnv.GetGraph()

    # See AddrUri() to understand the syntax of a socket name.
    socket_split = socket_nam.split(':')
    socket_addr = socket_split[0]

    try:
        socket_host = socket.gethostbyaddr(socket_addr)[0]
    except:
        socket_host = socket_addr

    # Maybe the port is given as a string, "ssh" or "telnet".
    # See usage of socket.getservbyport
    socket_port_string = socket_split[1]
    try:
        socket_port = int(socket_port_string)
    except ValueError:
        socket_port = socket.getservbyname(socket_port_string)

    # TCP is the default protocol.
    try:
        socket_transport = socket_split[2]
    except IndexError:
        socket_transport = "tcp"

    logging.debug("socket_addr=%s socket_port=%d", socket_addr, socket_port)
    # It uses the host name for the machine but an IP address for the socket.
    node_host = lib_uris.gUriGen.HostnameUri(socket_host)
    socket_node = lib_uris.gUriGen.AddrUri(socket_addr, socket_port)

    grph.add((node_host, pc.property_has_socket, socket_node))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
