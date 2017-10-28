#!/usr/bin/python

"""
Windows sessions established on a server
"""

import sys
import lib_util
import lib_common
from lib_properties import pc

import lib_win32
import win32net

Usable = lib_util.UsableWindows

def Main():
	cgiEnv = lib_common.CgiEnv()
	hostname = cgiEnv.GetId()

	nodeHost = lib_common.gUriGen.HostnameUri(hostname)

	grph = cgiEnv.GetGraph()

	# Return the name of the computer, name of the user, and active and idle times for the session.
	# No special group membership is required for level 0 or level 10 calls.
	level = 10

	try:
		# hostname = "Titi" for example
		lib_win32.WNetAddConnect(hostname)

		sessionList = win32net.NetSessionEnum(level, hostname)
	except Exception:
		lib_common.ErrorMessageHtml("Hostname="+hostname+". Exception:"+str(sys.exc_info()))

	for eltLst in sessionList:
		for keyLst in eltLst:
			valLst = eltLst[keyLst]
			grph.add( ( nodeHost, lib_common.MakeProp(keyLst), lib_common.NodeLiteral( valLst ) ) )

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
