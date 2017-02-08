#!/usr/bin/python

"""
List available RabbitMQ configurations
"""

import sys
import rdflib
import lib_common
import lib_util
import lib_credentials

from sources_types.rabbitmq import manager as survol_rabbitmq_manager

def Main():
	cgiEnv = lib_common.CgiEnv()

	#"RabbitMQ" : {
	#	"localhost:12345" : [ "guest", "guest" ]
	#	}
	credList = lib_credentials.GetCredentialsNames( "RabbitMQ" )

	grph = rdflib.Graph()

	if credList:
		for keyCred in credList:
			nodeManager = survol_rabbitmq_manager.MakeUri(keyCred)

			hostSplit = keyCred.split(":")

			nodeAddr = lib_common.gUriGen.AddrUri(hostSplit[0],hostSplit[1])

			grph.add( ( nodeAddr, lib_common.MakeProp("RabbitMQ manager"), nodeManager ) )

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()
