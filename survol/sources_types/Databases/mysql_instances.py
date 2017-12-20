#!/usr/bin/python

"""
mysql instances
"""

# This lists SQL servers from the credentials list.
# It does not attempt to connect to a server,
# and therefore does not need the appropriate packages.
# TODO: Detect servers with nmap.

import os
import sys
import re

import lib_util
import lib_common
import lib_credentials
from lib_properties import pc

# This does not import genuine mysql packages so this will always work.
from sources_types.mysql import instance as survol_mysql_instance

def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	credNames = lib_credentials.GetCredentialsNames( "MySql" )
	sys.stderr.write("Mysql servers\n")

	for instanceMySql in credNames:
		sys.stderr.write("WbemServersList instanceMySql=%s\n"%(instanceMySql))

		# Do not use sources_types.mysql
		hostMySql = instanceMySql.split(":")[0]

		# TODO: Display the connection socket ?
		nodeHostMySql = lib_common.gUriGen.HostnameUri( hostMySql )

		# Intentionaly, it does not use mysql package.
		# nodeInstance = lib_common.gUriGen.UriMakeFromDict("mysql/instance", { "Instance": instanceMySql } )
		nodeInstance = survol_mysql_instance.MakeUri(instanceMySql)

		aCred = lib_credentials.GetCredentials( "MySql", instanceMySql )

		grph.add( ( nodeInstance, pc.property_user, lib_common.NodeLiteral(aCred[0]) ) )
		grph.add( ( nodeInstance, lib_common.MakeProp("Mysql instance"), nodeHostMySql ) )



	try:
		pass
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("tnsnam="+tnsnam+" err="+str(exc))

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
