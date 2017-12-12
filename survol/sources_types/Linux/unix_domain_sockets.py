#!/usr/bin/python

"""
Unix domain sockets
"""

import os
import re
import sys
import lib_uris
import lib_common
from sources_types import CIM_DataFile
import lib_util
from lib_properties import pc

# The Python module psutil is not needed

# $ netstat -a --unix -p
# Active UNIX domain sockets (servers and established)
# Proto RefCnt Flags       Type       State         I-Node   PID/Program name     Path
# unix  2      [ ACC ]     STREAM     LISTENING     29819    1972/gnome-session   @/tmp/.ICE-unix/1972
# unix  2      [ ACC ]     STREAM     LISTENING     28085    1888/Xorg            @/tmp/.X11-unix/X0
# unix  2      [ ACC ]     STREAM     LISTENING     29463    1968/dbus-daemon     @/tmp/dbus-cpj6sQNfQb
# unix  2      [ ACC ]     STREAM     LISTENING     20787    -                    /run/user/42/pulse/native
# unix  2      [ ]         DGRAM                    27201    1784/systemd         /run/user/1000/systemd/notify
# unix  7      [ ]         DGRAM                    1362     -                    /run/systemd/journal/socket
# unix  2      [ ACC ]     STREAM     LISTENING     30806    -                    /run/user/1000/keyring/gpg
# unix  2      [ ACC ]     STREAM     LISTENING     30302    2075/pulseaudio      /run/user/1000/pulse/native


def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	propPidPath = lib_common.MakeProp("Process")
	propType = lib_common.MakeProp("Type")
	propState = lib_common.MakeProp("State")
	propINode = lib_common.MakeProp("INode")

	args = ["netstat", '-a', '--unix', '-p', ]
	pOpNetstat = lib_common.SubProcPOpen(args)

	(netstat_last_output, netstat_err) = pOpNetstat.communicate()

	asstr = netstat_last_output.decode("utf-8")

	sys.stderr.write("assstr:%s\n"%asstr)

	# Do not read the header on the first four lines.
	for lin in asstr.split('\n')[4:]:
		try:
			sockType = lin[25:36].strip()
			# sys.stderr.write("sockType %s\n"%sockType)
			sockState = lin[36:50].strip()
			# sys.stderr.write("sockState %s\n"%sockState)
			sockINode = lin[50:59].strip()
			# sys.stderr.write("sockINode %s\n"%sockINode)
			sockPath = lin[80:].strip()
		except :
			sys.stderr.write("Cannot parse:%s\n"%lin)
			continue

		if sockPath:
			nodePath = lib_common.gUriGen.FileUri(sockPath)
			grph.add( ( nodePath, propType, lib_common.NodeLiteral(sockType) ) )
			grph.add( ( nodePath, propState, lib_common.NodeLiteral(sockState) ) )
			grph.add( ( nodePath, propINode, lib_common.NodeLiteral(sockINode) ) )

		sockPidProg = lin[59:80].strip()
		if sockPidProg not in [ "-", "" ]:
			sockPidProgSplit = sockPidProg.split("/")
			sockPid = sockPidProgSplit[0]
			# sys.stderr.write("sockPid %s\n"%sockPid)
			sockProgNam = sockPidProgSplit[1]

			nodeProc = lib_common.gUriGen.PidUri(sockPid)
			if sockPath:
				grph.add( ( nodePath, propPidPath, nodeProc ) )
			# grph.add( ( nodeProc, pc.property_information, lib_common.NodeLiteral(sockProgNam) ) )

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()


