#!/usr/bin/python

"""
List queues in a RabbitMQ configuration
"""

import sys
import rdflib
import lib_common
import lib_credentials
from pyrabbit.api import Client
from sources_types.rabbitmq import manager as survol_rabbitmq_manager
from sources_types.rabbitmq import queue as survol_rabbitmq_queue

# It uses the port of the management interface:
# In rabbitmq.config:
# {rabbitmq_management,
#  [
#   {listener, [{port,     12345},
#               {ip,       "127.0.0.1"}]}

# rabbitmq-plugins enable rabbitmq_management

def Main():

	cgiEnv = lib_common.CgiEnv()

	configNam = cgiEnv.GetId()

	nodeManager = survol_rabbitmq_manager.MakeUri(configNam)

	creds = lib_credentials.GetCredentials( "RabbitMQ", configNam )

	# cl = Client('localhost:12345', 'guest', 'guest')
	cl = Client(configNam, creds[0], creds[1])

	grph = rdflib.Graph()

	# cl.is_alive()

	for qu in cl.get_queues():
		namQueue = qu["name"]
		sys.stdout.write("q=%s\n"%(namQueue))

		nodeQueue = survol_rabbitmq_queue.MakeUri(configNam,namQueue)

		grph.add( ( nodeQueue, lib_common.MakeProp("vhost"), rdflib.Literal(qu["vhost"]) ) )
		#for k in qu:
		#	v = qu[k]
		#	sys.stdout.write("%s=%s\n"%(k,v))

		grph.add( ( nodeManager, lib_common.MakeProp("Queue"), nodeQueue ) )


	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()
