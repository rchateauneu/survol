#!/usr/bin/python

"""
RabbitMQ connections
"""

import sys
import lib_common
import lib_credentials
from pyrabbit.api import Client
from sources_types import rabbitmq
from sources_types.rabbitmq import manager as survol_rabbitmq_manager
from sources_types.rabbitmq import user as survol_rabbitmq_user
from sources_types.rabbitmq import connection as survol_rabbitmq_connection

def Main():

	cgiEnv = lib_common.CgiEnv()

	configNam = cgiEnv.GetId()

	nodeManager = survol_rabbitmq_manager.MakeUri(configNam)

	creds = lib_credentials.GetCredentials( "RabbitMQ", configNam )

	# cl = Client('localhost:12345', 'guest', 'guest')
	cl = Client(configNam, creds[0], creds[1])

	grph = cgiEnv.GetGraph()

	# >>> cl.get_connections()[0]
	# http://localhost:12345/api/connections
	# {u'frame_max': 131072, u'send_pend': 0, u'protocol': u'AMQP 0-9-1', u'client_properties': {u'information': u'Licensed under the MPL.
	#   See http://www.rabbitmq.com/', u'product': u'RabbitMQ', u'copyright': u'Copyright (C) 2007-2014 GoPivotal, Inc.', u'capabilities':
	#  {u'exchange_exchange_bindings': True, u'connection.blocked': True, u'authentication_failure_close': True, u'basic.nack': True, u'co
	# nsumer_cancel_notify': True, u'publisher_confirms': True}, u'platform': u'.NET', u'version': u'4.5.2.30002'}, u'reductions': 9840145
	# , u'ssl_protocol': None, u'garbage_collection': {u'min_heap_size': 233, u'fullsweep_after': 65535, u'minor_gcs': 1, u'min_bin_vheap_
	# size': 46422}, u'peer_cert_validity': None, u'channels': 42, u'auth_mechanism': u'PLAIN', u'peer_cert_issuer': None, u'peer_cert_sub
	# ject': None, u'port': 5672, u'recv_oct_details': {u'rate': 29.4}, u'channel_max': 0, u'send_oct_details': {u'rate': 1140.8}, u'recv_
	# cnt': 69333, u'send_oct': 56500718, u'peer_host': u'127.0.0.1', u'state': u'running', u'ssl_cipher': None, u'type': u'network', u'no
	# de': u'rabbit@rchateau-HP', u'send_cnt': 69409, u'peer_port': 51532, u'ssl_hash': None, u'host': u'127.0.0.1', u'connected_at': 1486
	# 974214456L, u'user': u'guest', u'name': u'127.0.0.1:51532 -> 127.0.0.1:5672', u'ssl': False, u'vhost': u'/', u'recv_oct': 1461716, u
	# 'timeout': 60, u'ssl_key_exchange': None, u'reductions_details': {u'rate': 197.4}}


	try:
		#
		listConnections = cl.get_connections()
	except:
		#
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Caught:"+str(exc))

	for objConnect in listConnections:
		namConnect = objConnect["name"]

		sys.stderr.write("namConnect=%s\n"%(namConnect))

		#namConnectDisplay = namConnect.replace(">","&gt;")

		# namConnectCgi = namConnect.replace("_","+").replace(">","&gt;")
		#nodeConnect = survol_rabbitmq_connection.MakeUri(configNam,namConnectDisplay)
		nodeConnect = survol_rabbitmq_connection.MakeUri(configNam,namConnect)

		try:
			grph.add( ( nodeConnect, lib_common.MakeProp("Protocol"), lib_common.NodeLiteral(objConnect["protocol"]) ) )
		except KeyError:
			pass

		try:
			grph.add( ( nodeConnect, lib_common.MakeProp("Node"), lib_common.NodeLiteral(objConnect["node"]) ) )
		except KeyError:
			pass

		nodeUser = survol_rabbitmq_user.MakeUri(configNam,objConnect["user"])
		try:
			grph.add( ( nodeConnect, lib_common.MakeProp("User"), nodeUser ) )
		except KeyError:
			pass

		# '127.0.0.1:51532 -> 127.0.0.1:5672'
		# http://localhost:12345/#/connections/127.0.0.1%3A51532%20-%3E%20127.0.0.1%3A5672
		# namConnectCgi = namConnectDisplay
		namConnectCgi = namConnect.replace(">","&gt;")
		sys.stderr.write("namConnectCgi=%s\n"%(namConnectCgi))
		managementUrl = rabbitmq.ManagementUrlPrefix(configNam,"connections",namConnectCgi)

		grph.add( ( nodeConnect, lib_common.MakeProp("Management"), lib_common.NodeUrl(managementUrl) ) )

		grph.add( ( nodeManager, lib_common.MakeProp("Connection"), nodeConnect ) )


	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
