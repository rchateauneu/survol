#!/usr/bin/python

"""
RabbitMQ connection properties
"""

import sys
import rdflib
import lib_common
import lib_credentials
from six import string_types
from lib_properties import pc
from pyrabbit.api import Client
from sources_types import rabbitmq
from sources_types.rabbitmq import manager as survol_rabbitmq_manager
from sources_types.rabbitmq import connection as survol_rabbitmq_connection
from sources_types.rabbitmq import vhost as survol_rabbitmq_vhost
from sources_types.rabbitmq import user as survol_rabbitmq_user

def Main():

	cgiEnv = lib_common.CgiEnv()

	configNam = cgiEnv.m_entity_id_dict["Url"]
	namConnection = cgiEnv.m_entity_id_dict["Connection"]

	nodeManager = survol_rabbitmq_manager.MakeUri(configNam)

	creds = lib_credentials.GetCredentials( "RabbitMQ", configNam )

	# cl = Client('localhost:12345', 'guest', 'guest')
	cl = Client(configNam, creds[0], creds[1])

	grph = cgiEnv.GetGraph()

	sys.stderr.write("namConnection=%s\n"%(namConnection))

	#namConnectionDisplay = namConnection.replace(">","&gt;")
	#nodConnection = survol_rabbitmq_connection.MakeUri(configNam,namConnectionDisplay)
	nodConnection = survol_rabbitmq_connection.MakeUri(configNam,namConnection)

	grph.add( ( nodeManager, lib_common.MakeProp("Connection"), nodConnection ) )

	try:
		connectList = cl.get_connection(namConnection)
	except:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Caught:"+str(exc))

	for connectKey in connectList:
		connectVal = connectList[connectKey]

		if connectKey == "vhost":
			nodVHost = survol_rabbitmq_vhost.MakeUri(configNam,connectVal)
			grph.add( ( nodConnection, lib_common.MakeProp("Virtual host"), nodVHost ) )
		elif connectKey == "user":
			nodUser = survol_rabbitmq_user.MakeUri(configNam,connectVal)
			grph.add( ( nodConnection, lib_common.MakeProp("User"), nodUser ) )
		elif connectKey == "host":
			nodHost = lib_common.gUriGen.HostnameUri(connectVal)
			grph.add( ( nodConnection, lib_common.MakeProp("Host"), nodHost ) )
		elif connectKey in ["name","peer_host","peer_port"]:
			pass
		else:

			if isinstance(connectVal, string_types):
				connectVal = connectVal.replace(">","@") # .replace("{","@").replace("}","@")

				sys.stderr.write("connectKey=%s connectVal=%s\n"%(connectKey,connectVal))
			elif isinstance(connectVal, dict):
				pass
			elif isinstance(connectVal, tuple):
				pass
			elif isinstance(connectVal, list):
				pass
			else:
				pass

			sys.stderr.write("Literal=%s\n"%(rdflib.Literal(connectVal)))

			grph.add( ( nodConnection, lib_common.MakeProp(connectKey), rdflib.Literal(connectVal) ) )

			# Special processing ? Si on fait ca, tout les caracteres speciaux sont escapes.
			# grph.add( ( nodConnection, pc.property_rdf_data_nolist1, rdflib.Literal(connectVal) ) )


	# This is not useful apparently.
	# peerSocketNode = lib_common.gUriGen.AddrUri( connectList["peer_host"], connectList["peer_port"] )
	# grph.add( ( nodConnection, lib_common.MakeProp("Peer"), peerSocketNode ) )

	survol_rabbitmq_connection.AddSockets(grph,nodConnection,namConnection)

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
