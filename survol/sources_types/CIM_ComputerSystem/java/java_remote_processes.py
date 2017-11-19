#!/usr/bin/python

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
from sources_types import java as survol_java

from lib_properties import pc

def Main():

	cgiEnv = lib_common.CgiEnv( )
	hostname = cgiEnv.GetId()

	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	hostAddr = socket.gethostbyname(hostname)

	hostNode = lib_common.gUriGen.HostnameUri(hostname)

	for proc in CIM_Process.ProcessIter():
		pid = proc.pid

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
