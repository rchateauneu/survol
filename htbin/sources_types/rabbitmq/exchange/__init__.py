"""
RabbitMQ exchange
"""

import lib_common

def Graphic_colorbg():
	return "#CCCC66"

def EntityOntology():
	return ( ["Url","VHost","Exchange"], )

def MakeUri(urlName,vhostName,exchangeName):
	return lib_common.gUriGen.UriMakeFromDict("rabbitmq/exchange", { "Url" : urlName, "VHost" : vhostName, "Exchange" : exchangeName } )

def EntityName(entity_ids_arr,entity_host):
	return entity_ids_arr[0] + "/" + entity_ids_arr[1] + "/" + entity_ids_arr[2]
