"""
RabbitMQ user
"""

import lib_common

def Graphic_colorbg():
	return "#CC3366"

def EntityOntology():
	return ( ["Url","User"], )

def MakeUri(urlName,userName):
	return lib_common.gUriGen.UriMakeFromDict("rabbitmq/user", { "Url" : urlName, "User" : userName } )

def EntityName(entity_ids_arr,entity_host):
	return entity_ids_arr[0] + "/" + entity_ids_arr[1]
