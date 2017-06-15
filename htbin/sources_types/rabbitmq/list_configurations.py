#!/usr/bin/python

"""
List available RabbitMQ configurations
Configurations detected in the private credentials file.
"""

import sys
import rdflib
import lib_common
import lib_util
import lib_credentials

from sources_types import rabbitmq
from sources_types.rabbitmq import manager as survol_rabbitmq_manager

def Main():
	cgiEnv = lib_common.CgiEnv()

	#"RabbitMQ" : {
	#	"localhost:12345" : [ "guest", "guest" ]
	#	}
	credList = lib_credentials.GetCredentialsNames( "RabbitMQ" )

	grph = cgiEnv.GetGraph()

	if credList:
		for configNam in credList:
			nodeManager = survol_rabbitmq_manager.MakeUri(configNam)

			hostSplit = configNam.split(":")

			nodeAddr = lib_common.gUriGen.AddrUri(hostSplit[0],hostSplit[1])

			grph.add( ( nodeAddr, lib_common.MakeProp("RabbitMQ manager"), nodeManager ) )

			# http://127.0.0.1:12345/#/
			managementUrl = rabbitmq.ManagementUrlPrefix(configNam)
			grph.add( ( nodeAddr, lib_common.MakeProp("Management"), rdflib.URIRef(managementUrl) ) )

			# TODO: Get and display the log files.
			# Config file 	c:/Users/rchateau/AppData/Roaming/RabbitMQ/rabbitmq.config
			# Database directory 	c:/Users/rchateau/AppData/Roaming/RabbitMQ/db/RABBIT~1
			# Log file 	C:/Users/rchateau/AppData/Roaming/RabbitMQ/log/RABBIT~1.LOG
			# SASL log file 	C:/Users/rchateau/AppData/Roaming/RabbitMQ/log/RABBIT~2.LOG

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
