#!/usr/bin/env python

"""
TCP Windows sockets with netstat
"""

# Many advantages compared to psutil:
#   The Python module psutil is not needed
#   psutil gives only sockets if the process is accessible.
#   It is much faster.
# On the other it is necessary to run netstat in the shell.

import re
import sys
import socket
import logging

import lib_uris
import lib_util
import lib_common
from lib_properties import pc
from sources_types import addr as survol_addr

# C:\Users\rchateau>netstat -on
#
# Active Connections
#
#   Proto  Local Address          Foreign Address        State           PID
#   TCP    127.0.0.1:4369         127.0.0.1:51508        ESTABLISHED     3120
#   TCP    127.0.0.1:5357         127.0.0.1:54599        TIME_WAIT       0
#   TCP    [fe80::3c7a:339:64f0:2161%11]:1521  [fe80::3c7a:339:64f0:2161%11]:51769  ESTABLISHED     4316
#   TCP    [fe80::3c7a:339:64f0:2161%11]:51769  [fe80::3c7a:339:64f0:2161%11]:1521  ESTABLISHED     4776


def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    args = ["netstat", '-on', ]

    p = lib_common.SubProcPOpen(args)

    grph = cgiEnv.GetGraph()

    netstat_last_output, netstat_err = p.communicate()

    # Converts to string for Python3.
    netstat_str = netstat_last_output.decode("utf-8")
    netstat_lines = netstat_str.split('\n')

    seen_header = False
    for lin in netstat_lines:
        logging.debug("lin=%s",lin)

        # By default, consecutive spaces are treated as one.
        lin_split = lin.split()
        if len(lin_split) == 0:
            continue

        logging.debug("lin_split=%s", str(lin_split))

        if not seen_header:
            if len(lin_split) > 0 and lin_split[0] == "Proto":
                seen_header = True
            continue

        if lin_split[0] != "TCP":
            continue

        sock_status = lin_split[3]
        if sock_status != "ESTABLISHED":
            continue

        addr_local = lin_split[1]
        ip_local, port_local = survol_addr.SplitAddrPort(addr_local)


        # It does not use survol_addr.PsutilAddSocketToGraphOne(node_process,cnt,grph)
        # because sometimes we do not have the process id.

        local_socket_node = lib_uris.gUriGen.AddrUri(ip_local, port_local)
        grph.add((local_socket_node, pc.property_information, lib_util.NodeLiteral(sock_status)))

        addr_remot = lin_split[2]
        if addr_remot != "0.0.0.0:*":
            ip_remot, port_remot = survol_addr.SplitAddrPort(addr_remot)
            remot_socket_node = lib_uris.gUriGen.AddrUri(ip_remot, port_remot)
            grph.add((local_socket_node, pc.property_socket_end, remot_socket_node))

        proc_pid = lin_split[4]
        if proc_pid != "0":
            proc_node = lib_uris.gUriGen.PidUri(proc_pid)

            grph.add((proc_node, pc.property_host, lib_common.nodeMachine))
            grph.add((proc_node, pc.property_pid, lib_util.NodeLiteral(proc_pid)))

            grph.add((proc_node, pc.property_has_socket, local_socket_node))

        else:
            # If the local process is not known, just link the local socket to the local machine.
            grph.add((lib_common.nodeMachine, pc.property_host, local_socket_node))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()

