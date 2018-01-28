#!/usr/bin/python

"""
mysql instances on a server
"""

import sys
import re
import socket
import lib_util
import lib_common
import lib_credentials

from lib_properties import pc

# This does not import genuine mysql packages so this will always work.
from sources_types.mysql import instance as survol_mysql_instance

def Main():

	cgiEnv = lib_common.CgiEnv( )
	# instanceName = cgiEnv.GetId()
	# instanceName = cgiEnv.m_entity_id_dict["Instance"]
	hostname = cgiEnv.GetId()

	hostAddr = lib_util.GlobalGetHostByName(hostname)
	hostNode = lib_common.gUriGen.HostnameUri(hostname)

	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	propInstance = lib_common.MakeProp("Mysql instance")

	# Now it looks for Mysql instances which are hosted on this machine.
	credList = lib_credentials.GetCredentialsNames("MySql")
	for instanceName in credList:
		# This does not even need mysql package, so it can always detect instances.
		sqlInstHost = instanceName.split(":")[0].strip()

		if ( sqlInstHost != hostname ) and ( sqlInstHost != hostAddr ):
			sqlInstAddr = lib_util.GlobalGetHostByName(sqlInstHost)
			if ( sqlInstAddr != hostname ) and ( sqlInstAddr != hostAddr ):
				continue

		# Intentionaly, it does not use mysql package.
		# nodeInstance = lib_common.gUriGen.UriMakeFromDict("mysql/instance", { "Instance": instanceName } )
		nodeInstance = survol_mysql_instance.MakeUri(instanceName)

		grph.add( ( hostNode, propInstance, nodeInstance ) )

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
