"""
RabbitMQ user
"""

import lib_common
from sources_types.rabbitmq import manager as survol_rabbitmq_manager

def Graphic_colorbg():
	return "#FF3366"

def EntityOntology():
	return ( ["Url","VHost"], )

def MakeUri(urlName,vhostName):
	return lib_common.gUriGen.UriMakeFromDict("rabbitmq/vhost", { "Url" : urlName, "VHost" : vhostName } )

# According to the API documentation:
# "If the vhost is '/', note that it will be translated to '%2F' to conform to URL encoding requirements."
# https://pyrabbit.readthedocs.io/en/latest/api.html#pyrabbit.api.Client.get_queues
def EntityName(entity_ids_arr,entity_host):
	return entity_ids_arr[0] + "/" + entity_ids_arr[1]

# >>> cl.get_vhost("/")
# http://localhost:12345/api/vhosts/%2F
# {u'name': u'/', u'tracing': False, u'messages_details': {u'rate': 0.0}, u'messages': 0, u'message_stats': {u'deliver_no_ack': 0, u'p
# ublish_out': 0, u'get_no_ack': 13, u'return_unroutable': 0, u'confirm': 0, u'deliver_get': 13, u'publish': 13, u'confirm_details': {
# u'rate': 0.0}, u'ack_details': {u'rate': 0.0}, u'get': 0, u'deliver': 0, u'publish_out_details': {u'rate': 0.0}, u'redeliver_details
# ': {u'rate': 0.0}, u'deliver_details': {u'rate': 0.0}, u'deliver_get_details': {u'rate': 0.0}, u'publish_details': {u'rate': 0.0}, u
# 'publish_in_details': {u'rate': 0.0}, u'ack': 0, u'publish_in': 0, u'return_unroutable_details': {u'rate': 0.0}, u'get_details': {u'
# rate': 0.0}, u'get_no_ack_details': {u'rate': 0.0}, u'deliver_no_ack_details': {u'rate': 0.0}, u'redeliver': 0}, u'messages_unacknow
# ledged_details': {u'rate': 0.0}, u'messages_ready_details': {u'rate': 0.0}, u'messages_unacknowledged': 0, u'messages_ready': 0}
def AddInfo(grph,node,entity_ids_arr):
	namConfig = entity_ids_arr[0]

	nodeManager = survol_rabbitmq_manager.MakeUri(namConfig)

	# Inverted property for nicer display.
	grph.add( ( node, lib_common.MakeProp("Configuration manager"), nodeManager ) )
