"""
RabbitMQ client connection
"""

import sys
import lib_common
from lib_properties import pc
from sources_types.rabbitmq import manager as survol_rabbitmq_manager

def Graphic_colorbg():
	return "#FFCC33"

def EntityOntology():
	return ( ["Url","Connection"], )

def MakeUri(urlName,connectionName):
	return lib_common.gUriGen.UriMakeFromDict("rabbitmq/connection", { "Url" : urlName, "Connection" : connectionName } )

# '127.0.0.1:51532 -> 127.0.0.1:5672'
def EntityName(entity_ids_arr,entity_host):
	return entity_ids_arr[0] + "/" + entity_ids_arr[1].replace(">","&gt;")

# Adds the sockets, as their address is embedded in the connection name,
# so no need to query RabbitMQ library.
def AddSockets(grph,node,namConnection):
	namConnectSplit = namConnection.split("->")

	def MakeSocketNode(hostColonPort):
		# "127.0.0.1:51532"
		socketSplit = hostColonPort.strip().split(":")
		socketNode = lib_common.gUriGen.AddrUri( socketSplit[0], socketSplit[1] )
		return socketNode

	lsocketNode = MakeSocketNode(namConnectSplit[0])
	rsocketNode = MakeSocketNode(namConnectSplit[1])

	grph.add( ( node, pc.property_has_socket, lsocketNode ) )
	grph.add( ( lsocketNode, pc.property_socket_end, rsocketNode ) )

def AddInfo(grph,node,entity_ids_arr):
	namConfig = entity_ids_arr[0]
	namConnection = entity_ids_arr[1]

	AddSockets(grph,node,namConnection)

	# Then add the manager node.
	nodeManager = survol_rabbitmq_manager.MakeUri(namConfig)

	# Inverted property for nicer display.
	grph.add( ( node, lib_common.MakeProp("Configuration manager"), nodeManager ) )


