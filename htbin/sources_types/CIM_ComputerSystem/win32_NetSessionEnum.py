#!/usr/bin/python

"""
Windows sessions established on a server
"""

import sys
import rdflib
import lib_util
import lib_common
from lib_properties import pc

import win32net

Usable = lib_util.UsableWindows

def Main():
	cgiEnv = lib_common.CgiEnv()
	hostname = cgiEnv.GetId()

	nodeHost = lib_common.gUriGen.HostnameUri(hostname)

	grph = rdflib.Graph()

	# Return the name of the computer, name of the user, and active and idle times for the session.
	# No special group membership is required for level 0 or level 10 calls.
	level = 10

	try:
		sessionList = win32net.NetSessionEnum(level, hostname)
	except Exception:
		lib_common.ErrorMessageHtml("Hostname="+hostname+". Exception:"+str(sys.exc_info()))

	for machine in sessionList:
		userName = machine["user_name"]

		grph.add( ( nodeHost, pc.property_information, rdflib.Literal( str(machine) ) ) )


	# grph.add( ( nodeHost, pc.property_smbshare, shareNode ) )
	# grph.add( ( shareNode, pc.property_information, rdflib.Literal(share_remark) ) )

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()
