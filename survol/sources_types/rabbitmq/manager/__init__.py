"""
RabbitMQ configuration
"""

import lib_common

def Graphic_colorbg():
	return "#FFCC66"

def EntityOntology():
	return ( ["Url",], )

def MakeUri(urlName):
	return lib_common.gUriGen.UriMakeFromDict("rabbitmq/manager", { "Url" : urlName } )

def EntityName(entity_ids_arr,entity_host):
	return entity_ids_arr[0]
