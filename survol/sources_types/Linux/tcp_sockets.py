#!/usr/bin/python

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

#

def Main():
	cgiEnv = lib_common.CgiEnv()

	args = ["netstat", '-aptn', ]

	p = lib_common.SubProcPOpen(args)

	grph = cgiEnv.GetGraph()

	(netstat_last_output, netstat_err) = p.communicate()

	# Converts to string for Python3.
	netstat_str = netstat_last_output.decode("utf-8")
	netstat_lines = netstat_str.split('\n')

	seenHeader = False
	for lin in netstat_lines:
		# By default, consecutive spaces are treated as one.
		linSplit = lin.split()

		if len(linSplit) == 0:
			continue

		if not seenHeader:
			if linSplit[0] == "Proto":
				seenHeader = True
			continue

		# TODO: "tcp6"
		if linSplit[0] != "tcp":
			continue

    		# sys.stderr.write("tcp_sockets.py lin=%s\n"%lin)

		sockStatus = linSplit[5]
		if sockStatus not in ["ESTABLISHED","TIME_WAIT"]:
			continue

		addrLocal = linSplit[3]
		ipLocal, portLocal = survol_addr.SplitAddrPort(addrLocal)

		# It does not use survol_addr.PsutilAddSocketToGraphOne(node_process,cnt,grph)
		# because sometimes we do not have the process id.

		localSocketNode = lib_common.gUriGen.AddrUri( ipLocal, portLocal )
		grph.add( ( localSocketNode, pc.property_information, lib_common.NodeLiteral(sockStatus) ) )

		addrRemot = linSplit[4]

		# This is different for IPV6
		if addrRemot != "0.0.0.0:*":
			ipRemot, portRemot = survol_addr.SplitAddrPort(addrRemot)
			remotSocketNode = lib_common.gUriGen.AddrUri( ipRemot, portRemot )
			grph.add( ( localSocketNode, pc.property_socket_end, remotSocketNode ) )

		pidCommand = linSplit[6]
		if pidCommand != "-":
			procPid, procNam = pidCommand.split("/")
			procNode = lib_common.gUriGen.PidUri(procPid)

			grph.add( ( procNode, pc.property_host, lib_common.nodeMachine ) )
			grph.add( ( procNode, pc.property_pid, lib_common.NodeLiteral(procPid) ) )

			grph.add( ( procNode, pc.property_has_socket, localSocketNode ) )

		else:
			# If the local process is not known, just link the local socket to the local machine.
			grph.add( ( lib_common.nodeMachine, pc.property_host, localSocketNode ) )


	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
