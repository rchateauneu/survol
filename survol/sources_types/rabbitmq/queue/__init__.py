"""
RabbitMQ queue
"""

import lib_common
from sources_types.rabbitmq import manager as survol_rabbitmq_manager
from sources_types.rabbitmq import vhost as survol_rabbitmq_vhost

def Graphic_colorbg():
	return "#CCCC66"

def EntityOntology():
	return ( ["Url","VHost","Queue"], )

def MakeUri(urlName,vhostName,queueName):
	return lib_common.gUriGen.UriMakeFromDict("rabbitmq/queue", { "Url" : urlName, "VHost" : vhostName, "Queue" : queueName } )

def EntityName(entity_ids_arr,entity_host):
	return entity_ids_arr[0] + "/" + entity_ids_arr[1] + "/" + entity_ids_arr[2]

def AddInfo(grph,node,entity_ids_arr):
	namConfig = entity_ids_arr[0]
	namVHost = entity_ids_arr[1]

	nodeManager = survol_rabbitmq_manager.MakeUri(namConfig)

	nodVHost = survol_rabbitmq_vhost.MakeUri(namConfig,namVHost)
	grph.add( ( nodeManager, lib_common.MakeProp("virtual host node"), nodVHost ) )

	grph.add( ( node, lib_common.MakeProp("Manager"), nodeManager ) )
	grph.add( ( node, lib_common.MakeProp("Virtual host"), nodVHost ) )
