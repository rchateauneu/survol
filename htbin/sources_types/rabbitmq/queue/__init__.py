"""
RabbitMQ queue
"""

import lib_common

def Graphic_colorbg():
	return "#CCCC66"

def EntityOntology():
	return ( ["Url","Queue"], )

def MakeUri(urlName,queueName):
	return lib_common.gUriGen.UriMakeFromDict("rabbitmq/queue", { "Url" : urlName, "Queue" : queueName } )

def EntityName(entity_ids_arr,entity_host):
	return entity_ids_arr[0] + "/" + entity_ids_arr[1]
