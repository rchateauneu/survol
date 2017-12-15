#!/usr/bin/python

"""
MySql servers
"""

# This lists SQL servers from the credentials list.
# It does not attempt to connect to a server,
# and therefore does not need the appropriated packages.
# TODO: Detect servers with nmap.

import os
import sys
import re

import lib_util
import lib_common
import lib_credentials
from lib_properties import pc

def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	credNames = lib_credentials.GetCredentialsNames( "MySql" )
	sys.stderr.write("Mysql servers\n")

    #"primhilltcsrvdb1.mysql.db": [
    #  "primhilltcsrvdb1",
    #  "xyz"
    #],

	for hostMySql in credNames:
		sys.stderr.write("WbemServersList hostMySql=%s\n"%(hostMySql))

		nodeHostMySql = lib_common.gUriGen.HostnameUri( hostMySql )

		aCred = lib_credentials.GetCredentials("MySql", hostMySql)

		grph.add( ( nodeHostMySql, pc.property_user, lib_common.NodeLiteral(aCred[0]) ) )

	try:
		pass
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("tnsnam="+tnsnam+" err="+str(exc))

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
