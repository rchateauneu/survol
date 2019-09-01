#!/usr/bin/env python

"""
Configuration overview
"""

import sys
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

	grph = cgiEnv.GetGraph()

	try:
		#
		lstOverview = cl.get_overview()
	except:
		#
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Caught:"+str(exc))

	for keyOverview in lstOverview:
		valOverview = lstOverview[keyOverview]

		# grph.add( ( nodeManager, lib_common.MakeProp(keyOverview), lib_common.NodeLiteral(valOverview) ) )
		valClean = valOverview
		# Otherwise it does not work as these chars should be espaced.
		# TODO: Nice display for Python lists and dicts.
		valClean = str(valClean).replace("{","").replace("}","")
		# sys.stderr.write("valClean=%s\n"%valClean)
		grph.add( ( nodeManager, lib_common.MakeProp(keyOverview), lib_common.NodeLiteral(valClean) ) )

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
