#!/usr/bin/env python

"""
TCP Linux sockets with netstat
"""

import re
import sys
import socket
import lib_util
import lib_common
from lib_properties import pc
from sources_types import addr as survol_addr

# Many advantages compared to psutil:
#   The Python module psutil is not needed
#   psutil gives only sockets if the process is accessible.
#   It is much faster.
# On the other it is necessary to run netstat in the shell.

# $ netstat -aptn
# (Not all processes could be identified, non-owned process info
#  will not be shown, you would have to be root to see it all.)
# Active Internet connections (servers and established)
# Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
# tcp        0      0 192.168.0.17:8000       0.0.0.0:*               LISTEN      25865/python
# tcp        0      0 127.0.0.1:427           0.0.0.0:*               LISTEN      -
# tcp        0      0 0.0.0.0:5900            0.0.0.0:*               LISTEN      4119/vino-server
# tcp        0      0 192.168.122.1:53        0.0.0.0:*               LISTEN      -
# tcp        0      0 192.168.0.17:44634      192.168.0.14:60685      ESTABLISHED 4118/rygel
# tcp        0      0 192.168.0.17:22         192.168.0.14:60371      ESTABLISHED -
# tcp        0      0 192.168.0.17:44634      192.168.0.14:58478      ESTABLISHED 4118/rygel
# tcp        0      0 192.168.0.17:44634      192.168.0.15:38960      TIME_WAIT   -
# tcp        0      0 192.168.0.17:44634      192.168.0.14:58658      ESTABLISHED 4118/rygel
# tcp        0      0 192.168.0.17:44634      192.168.0.14:59694      ESTABLISHED 4118/rygel
# tcp        0      0 fedora22:44634          192.168.0.14:58690      ESTABLISHED 4118/rygel
# tcp        0      0 fedora22:ssh            192.168.0.14:63599      ESTABLISHED -
# tcp        0      0 fedora22:42042          176.103.:universe_suite ESTABLISHED 23512/amule
# tcp6       0      0 [::]:wbem-http          [::]:*                  LISTEN      -
# tcp6       0      0 [::]:wbem-https         [::]:*                  LISTEN      -
# tcp6       0      0 [::]:mysql              [::]:*                  LISTEN      -
# tcp6       0      0 [::]:rfb                [::]:*                  LISTEN      4119/vino-server
# tcp6       0      0 [::]:50000              [::]:*                  LISTEN      23512/amule
# tcp6       0      0 [::]:43056              [::]:*                  LISTEN      4125/httpd
# tcp6       0      0 [::]:http               [::]:*                  LISTEN      -
# tcp6       0      0 [::]:ssh                [::]:*                  LISTEN      -
# tcp6       0      0 localhost:ipp           [::]:*                  LISTEN      -
# tcp6       0      0 [::]:telnet             [::]:*                  LISTEN      -


def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    args = ["netstat", '-aptn',]

    p = lib_common.SubProcPOpen(args)

    grph = cgiEnv.GetGraph()

    netstat_last_output, netstat_err = p.communicate()

    # Converts to string for Python3.
    netstat_str = netstat_last_output.decode("utf-8")
    netstat_lines = netstat_str.split('\n')

    seen_header = False
    for lin in netstat_lines:
        # By default, consecutive spaces are treated as one.
        lin_split = lin.split()

        if len(lin_split) == 0:
            continue

        if not seen_header:
            if lin_split[0] == "Proto":
                seen_header = True
            continue

        # TODO: "tcp6"
        if lin_split[0] != "tcp":
            continue

        sock_status = lin_split[5]
        if sock_status not in ["ESTABLISHED", "TIME_WAIT"]:
            continue

        addr_local = lin_split[3]
        ip_local, port_local = survol_addr.SplitAddrPort(addr_local)

        # It does not use survol_addr.PsutilAddSocketToGraphOne(node_process,cnt,grph)
        # because sometimes we do not have the process id.

        local_socket_node = lib_common.gUriGen.AddrUri(ip_local, port_local)
        grph.add((local_socket_node, pc.property_information, lib_util.NodeLiteral(sock_status)))

        addr_remot = lin_split[4]

        # This is different for IPV6
        if addr_remot != "0.0.0.0:*":
            ip_remot, port_remot = survol_addr.SplitAddrPort(addr_remot)
            remot_socket_node = lib_common.gUriGen.AddrUri(ip_remot, port_remot)
            grph.add((local_socket_node, pc.property_socket_end, remot_socket_node))

        pid_command = lin_split[6]
        if pid_command != "-":
            proc_pid, proc_nam = pid_command.split("/")
            proc_node = lib_common.gUriGen.PidUri(proc_pid)

            grph.add((proc_node, pc.property_host, lib_common.nodeMachine))
            grph.add((proc_node, pc.property_pid, lib_util.NodeLiteral(proc_pid)))

            grph.add((proc_node, pc.property_has_socket, local_socket_node))

        else:
            # If the local process is not known, just link the local socket to the local machine.
            grph.add((lib_common.nodeMachine, pc.property_host, local_socket_node))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
