"""
RabbitMQ configuration
"""

import lib_common

def Graphic_colorbg():
	return "#FFCC66"

def EntityOntology():
	return ( ["Url",], )

def MakeUri(urlName):
	# This URL is nothing but a host:port.
	# The host is case-insensitive.
	urlName = urlName.lower()
	return lib_common.gUriGen.UriMakeFromDict("rabbitmq/manager", { "Url" : urlName } )

def EntityName(entity_ids_arr):
	return entity_ids_arr[0]
