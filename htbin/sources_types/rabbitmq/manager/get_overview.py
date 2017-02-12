#!/usr/bin/python

"""
Configuration overview
"""

import sys
import rdflib
import lib_common
import lib_credentials
from pyrabbit.api import Client
from sources_types.rabbitmq import manager as survol_rabbitmq_manager

def Main():

	cgiEnv = lib_common.CgiEnv()

	configNam = cgiEnv.GetId()

	nodeManager = survol_rabbitmq_manager.MakeUri(configNam)

	creds = lib_credentials.GetCredentials( "RabbitMQ", configNam )

	# cl = Client('localhost:12345', 'guest', 'guest')
	cl = Client(configNam, creds[0], creds[1])

	grph = rdflib.Graph()

	lstOverview = cl.get_overview()
	for keyOverview in lstOverview:
		valOverview = lstOverview[keyOverview]

		grph.add( ( nodeManager, lib_common.MakeProp(keyOverview), rdflib.Literal(valOverview) ) )

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()
