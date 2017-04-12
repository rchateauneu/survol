#!/usr/bin/python

"""
RabbitMQ exchanges
"""

import sys
import rdflib
import lib_common
import lib_credentials
from pyrabbit.api import Client
from sources_types import rabbitmq
from sources_types.rabbitmq import manager as survol_rabbitmq_manager
from sources_types.rabbitmq import exchange as survol_rabbitmq_exchange
from sources_types.rabbitmq import vhost as survol_rabbitmq_vhost

def Main():

	cgiEnv = lib_common.CgiEnv()

	configNam = cgiEnv.m_entity_id_dict["Url"]
	# namVHost = cgiEnv.m_entity_id_dict["VHost"]


	nodeManager = survol_rabbitmq_manager.MakeUri(configNam)

	creds = lib_credentials.GetCredentials( "RabbitMQ", configNam )

	# cl = Client('localhost:12345', 'guest', 'guest')
	cl = Client(configNam, creds[0], creds[1])

	grph = rdflib.Graph()

	try:
		#
		listExchanges = cl.get_exchanges()
	except:
		#
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Caught:"+str(exc))

	for objExchange in listExchanges:
		namExchange = objExchange["name"]
		sys.stderr.write("namExchange=%s\n"%(namExchange))

		namVHost = objExchange["vhost"]
		nodeExchange = survol_rabbitmq_exchange.MakeUri(configNam,namVHost,namExchange)

		nodVHost = survol_rabbitmq_vhost.MakeUri(configNam,namVHost)
		grph.add( ( nodeExchange, lib_common.MakeProp("virtual host node"), nodVHost ) )

		managementUrl = rabbitmq.ManagementUrlPrefix(configNam,"exchanges",namVHost,namExchange)

		grph.add( ( nodeExchange, lib_common.MakeProp("Management"), rdflib.URIRef(managementUrl) ) )

		grph.add( ( nodVHost, lib_common.MakeProp("Exchange"), nodeExchange ) )


	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()
