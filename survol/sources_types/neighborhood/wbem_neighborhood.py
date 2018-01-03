#!/usr/bin/python

"""
Neighboring WBEM agents.
"""

import sys
import lib_util
import lib_common
import lib_credentials

# TODO: SLP to detect machines.

def AddWbemNode(grph,hostWbem,urlWbemClean):
	sys.stderr.write("AddWbemNode hostWbem=%s\n"%(hostWbem))
	lib_common.ErrorMessageHtml("AddWbemNode not implemented yet" )

def WbemServersDisplay(grph):
	lstWbemServers = []
	credNames = lib_credentials.GetCredentialsNames( "WBEM" )
	sys.stderr.write("WbemServersDisplay\n")
	for urlWbem in credNames:
		sys.stderr.write("WbemServersDisplay urlWbem=%s\n"%(urlWbem))

		# The credentials are not needed until a Survol agent uses HTTPS.
		parsed_url = lib_util.survol_urlparse( urlWbem )
		hostWbem = parsed_url.hostname
		# sys.stderr.write("WbemServersDisplay hostWbem=%s\n"%(hostWbem))
		if not hostWbem:
			continue

		AddWbemNode(grph,hostWbem,urlWbem)

def Main():

	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	WbemServersDisplay(grph)

	cgiEnv.OutCgiRdf()


if __name__ == '__main__':
	Main()
