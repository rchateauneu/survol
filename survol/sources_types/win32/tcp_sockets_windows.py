#!/usr/bin/python

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
	cgiEnv = lib_common.CgiEnv()

	args = ["netstat", '-on', ]

	p = lib_common.SubProcPOpen(args)

	grph = cgiEnv.GetGraph()

	(netstat_last_output, netstat_err) = p.communicate()

	# Converts to string for Python3.
	netstat_str = netstat_last_output.decode("utf-8")
	netstat_lines = netstat_str.split('\n')

	seenHeader = False
	for lin in netstat_lines:
		sys.stderr.write("lin=%s\n"%lin)

		# By default, consecutive spaces are treated as one.
		linSplit = lin.split()
		if len(linSplit) == 0:
			continue

		sys.stderr.write("linSplit=%s\n"%str(linSplit))

		if not seenHeader:
			if len(linSplit) > 0 and linSplit[0] == "Proto":
				seenHeader = True
			continue

		if linSplit[0] != "TCP":
			continue

		sockStatus = linSplit[3]
		if sockStatus != "ESTABLISHED":
			continue


		addrLocal = linSplit[1]
		ipLocal, portLocal = survol_addr.SplitAddrPort(addrLocal)


		# It does not use survol_addr.PsutilAddSocketToGraphOne(node_process,cnt,grph)
		# because sometimes we do not have the process id.

		localSocketNode = lib_common.gUriGen.AddrUri( ipLocal, portLocal )
		grph.add( ( localSocketNode, pc.property_information, lib_common.NodeLiteral(sockStatus) ) )

		addrRemot = linSplit[2]
		if addrRemot != "0.0.0.0:*":
			ipRemot, portRemot = survol_addr.SplitAddrPort(addrRemot)
			remotSocketNode = lib_common.gUriGen.AddrUri( ipRemot, portRemot )
			grph.add( ( localSocketNode, pc.property_socket_end, remotSocketNode ) )

		procPid = linSplit[4]
		if procPid != "0":
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

