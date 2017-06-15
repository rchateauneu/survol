#!/usr/bin/python

"""
RabbitMQ virtual hosts queues
"""

import sys
import rdflib
import lib_common
import lib_credentials
from pyrabbit.api import Client
from sources_types import rabbitmq
from sources_types.rabbitmq import manager as survol_rabbitmq_manager
from sources_types.rabbitmq import queue as survol_rabbitmq_queue
from sources_types.rabbitmq import vhost as survol_rabbitmq_vhost

# It uses the port of the management interface:
# In rabbitmq.config:
# {rabbitmq_management,
#  [
#   {listener, [{port,     12345},
#               {ip,       "127.0.0.1"}]}

# rabbitmq-plugins enable rabbitmq_management

def Main():

	cgiEnv = lib_common.CgiEnv()

	configNam = cgiEnv.m_entity_id_dict["Url"]
	namVHost = cgiEnv.m_entity_id_dict["VHost"]


	nodeManager = survol_rabbitmq_manager.MakeUri(configNam)

	creds = lib_credentials.GetCredentials( "RabbitMQ", configNam )

	# cl = Client('localhost:12345', 'guest', 'guest')
	cl = Client(configNam, creds[0], creds[1])

	grph = cgiEnv.GetGraph()

	nodVHost = survol_rabbitmq_vhost.MakeUri(configNam,namVHost)
	grph.add( ( nodeManager, lib_common.MakeProp("virtual host node"), nodVHost ) )

	for quList in cl.get_queues(namVHost):
		namQueue = quList["name"]
		sys.stderr.write("q=%s\n"%(namQueue))

		nodeQueue = survol_rabbitmq_queue.MakeUri(configNam,namVHost,namQueue)

		managementUrl = rabbitmq.ManagementUrlPrefix(configNam,"queues",namVHost,namQueue)

		grph.add( ( nodeQueue, lib_common.MakeProp("Management"), rdflib.URIRef(managementUrl) ) )

		grph.add( ( nodVHost, lib_common.MakeProp("Queue"), nodeQueue ) )


	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()
