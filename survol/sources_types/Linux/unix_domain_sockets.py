#!/usr/bin/env python

"""
Unix domain sockets
"""

import os
import re
import sys
import logging
import lib_uris
import lib_common
from sources_types import CIM_DataFile
import lib_util
from lib_properties import pc

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

    prop_pid_path = lib_common.MakeProp("Process")
    prop_type = lib_common.MakeProp("Type")
    prop_state = lib_common.MakeProp("State")
    prop_inode = lib_common.MakeProp("INode")

    args = ["netstat", '-a', '--unix', '-p',]
    pOpNetstat = lib_common.SubProcPOpen(args)

    netstat_last_output, netstat_err = pOpNetstat.communicate()

    asstr = netstat_last_output.decode("utf-8")

    # Do not read the header on the first four lines.
    for lin in asstr.split('\n')[4:]:
        try:
            sock_type = lin[25:36].strip()
            # sys.stderr.write("sock_type %s\n"%sock_type)
            sock_state = lin[36:50].strip()
            # sys.stderr.write("sock_state %s\n"%sock_state)
            sock_inode = lin[50:59].strip()
            # sys.stderr.write("sock_inode %s\n"%sock_inode)
            sock_path = lin[80:].strip()
        except :
            logging.warning("Cannot parse:%s",lin)
            continue

        if sock_path:
            node_path = lib_common.gUriGen.FileUri(sock_path)
            grph.add((node_path, prop_type, lib_util.NodeLiteral(sock_type)))
            grph.add((node_path, prop_state, lib_util.NodeLiteral(sock_state)))
            grph.add((node_path, prop_inode, lib_util.NodeLiteral(sock_inode)))

        sock_pid_prog = lin[59:80].strip()
        if sock_pid_prog not in ["-", ""]:
            sock_pid_prog_split = sock_pid_prog.split("/")
            sock_pid = sock_pid_prog_split[0]
            # sys.stderr.write("sock_pid %s\n"%sock_pid)

            # Not used, and index error on Python 3.
            # sockProgNam = sock_pid_prog_split[1]

            node_proc = lib_common.gUriGen.PidUri(sock_pid)
            if sock_path:
                grph.add((node_path, prop_pid_path, node_proc))
            # grph.add( ( node_proc, pc.property_information, lib_util.NodeLiteral(sockProgNam) ) )

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()


