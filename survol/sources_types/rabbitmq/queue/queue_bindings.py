#!/usr/bin/python

"""
RabbitMQ queue bindings
"""

import sys
import lib_common
import lib_credentials
from pyrabbit.api import Client
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
	namQueue = cgiEnv.m_entity_id_dict["Queue"]

	nodeManager = survol_rabbitmq_manager.MakeUri(configNam)

	creds = lib_credentials.GetCredentials( "RabbitMQ", configNam )

	# cl = Client('localhost:12345', 'guest', 'guest')
	cl = Client(configNam, creds[0], creds[1])

	grph = cgiEnv.GetGraph()

	nodVHost = survol_rabbitmq_vhost.MakeUri(configNam,namVHost)
	grph.add( ( nodeManager, lib_common.MakeProp("virtual host node"), nodVHost ) )

	nodeQueue = survol_rabbitmq_queue.MakeUri(configNam,namVHost,namQueue)
	grph.add( ( nodVHost, lib_common.MakeProp("Queue"), nodeQueue ) )

	# >>> cl.get_queue_bindings("/","aliveness-test")
	# [{u'vhost': u'/', u'properties_key': u'aliveness-test', u'destination': u'aliveness-test', u'routing_key': u'aliveness-test', u'sour
	# ce': u'', u'arguments': {}, u'destination_type': u'queue'}]
	lstBindings = cl.get_queue_bindings(namVHost,namQueue)

	for sublstBindings in lstBindings:
		for keyBindings in sublstBindings:
			valBindings = sublstBindings[keyBindings]
			strDisp = str(valBindings).replace("{","").replace("}","")
			grph.add( ( nodeQueue, lib_common.MakeProp(keyBindings), lib_common.NodeLiteral(strDisp ) ))
			DEBUG("keyBindings=%s valBindings=%s",keyBindings,valBindings)

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
