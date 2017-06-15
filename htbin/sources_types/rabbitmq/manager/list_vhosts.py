#!/usr/bin/python

"""
RabbitMQ virtual hosts
"""

import sys
import rdflib
import lib_common
import lib_credentials
from pyrabbit.api import Client
from sources_types import rabbitmq
from sources_types.rabbitmq import manager as survol_rabbitmq_manager
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

	configNam = cgiEnv.GetId()

	nodeManager = survol_rabbitmq_manager.MakeUri(configNam)

	creds = lib_credentials.GetCredentials( "RabbitMQ", configNam )

	# cl = Client('localhost:12345', 'guest', 'guest')
	cl = Client(configNam, creds[0], creds[1])

	grph = cgiEnv.GetGraph()

	# >>> cl.get_all_vhosts()
	# http://localhost:12345/api/vhosts
	# [{u'name': u'/', u'tracing': False, u'messages_details': {u'rate': 0.0}, u'messages': 0, u'message_stats': {u'deliver_no_ack': 0, u'
	# publish_out': 0, u'get_no_ack': 13, u'return_unroutable': 0, u'confirm': 0, u'deliver_get': 13, u'publish': 13, u'confirm_details':
	# {u'rate': 0.0}, u'ack_details': {u'rate': 0.0}, u'get': 0, u'deliver': 0, u'publish_out_details': {u'rate': 0.0}, u'redeliver_detail
	# s': {u'rate': 0.0}, u'deliver_details': {u'rate': 0.0}, u'deliver_get_details': {u'rate': 0.0}, u'publish_details': {u'rate': 0.0},
	# u'publish_in_details': {u'rate': 0.0}, u'ack': 0, u'publish_in': 0, u'return_unroutable_details': {u'rate': 0.0}, u'get_details': {u
	# 'rate': 0.0}, u'get_no_ack_details': {u'rate': 0.0}, u'deliver_no_ack_details': {u'rate': 0.0}, u'redeliver': 0}, u'messages_unackno
	# wledged_details': {u'rate': 0.0}, u'messages_ready_details': {u'rate': 0.0}, u'messages_unacknowledged': 0, u'messages_ready': 0}]

	try:
		#
		listVHosts = cl.get_all_vhosts()
	except:
		#
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Caught:"+str(exc))

	for objVHost in listVHosts:
		namVHost = objVHost["name"]
		sys.stderr.write("q=%s\n"%(namVHost))

		nodeVHost = survol_rabbitmq_vhost.MakeUri(configNam,namVHost)

		try:
			grph.add( ( nodeVHost, lib_common.MakeProp("tracing"), rdflib.Literal(objVHost["tracing"]) ) )
		except KeyError:
			pass

		try:
			grph.add( ( nodeVHost, lib_common.MakeProp("messages"), rdflib.Literal(objVHost["messages"]) ) )
		except KeyError:
			pass

		# http://127.0.0.1:12345/#/vhosts//
		managementUrl = rabbitmq.ManagementUrlPrefix(configNam,"vhosts",namVHost)

		grph.add( ( nodeVHost, lib_common.MakeProp("Management"), rdflib.URIRef(managementUrl) ) )


		grph.add( ( nodeManager, lib_common.MakeProp("Virtual host"), nodeVHost ) )


	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
