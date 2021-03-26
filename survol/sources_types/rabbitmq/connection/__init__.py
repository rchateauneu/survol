"""
RabbitMQ client connection
"""

import sys

import lib_uris
import lib_common
from lib_properties import pc
from sources_types.rabbitmq import manager as survol_rabbitmq_manager


def Graphic_colorbg():
    return "#FFCC33"


def EntityOntology():
    return (["Url", "Connection"],)


def MakeUri(url_name, connection_name):
    # The url is a host:port pair, and the host is case-insensitive.
    url_name = url_name.lower()
    # Needed because RabbitMQ connecton names are like:
    # "Url=LOCALHOST:12345,Connection=127.0.0.1:51748 -> 127.0.0.1:5672"
    connection_name = connection_name.replace(">", "&gt;")
    return lib_uris.gUriGen.UriMakeFromDict("rabbitmq/connection", {"Url": url_name, "Connection": connection_name})


# '127.0.0.1:51532 -> 127.0.0.1:5672'
def EntityName(entity_ids_arr):
    return entity_ids_arr[0] + "/" + entity_ids_arr[1].replace(">", "&gt;")


# Adds the sockets, as their address is embedded in the connection name,
# so no need to query RabbitMQ library.
# Example: namConnection = "127.0.0.1::51748 -> 127.0.0.1:5672"
def AddSockets(grph, node, nam_connection):
    nam_connect_split = nam_connection.split("->")

    def make_socket_node(host_colon_port):
        # "127.0.0.1:51532"
        socket_split = host_colon_port.strip().split(":")
        socket_node = lib_uris.gUriGen.AddrUri(socket_split[0], socket_split[1])
        return socket_node

    lsocket_node = make_socket_node(nam_connect_split[0])
    rsocket_node = make_socket_node(nam_connect_split[1])

    grph.add((node, pc.property_has_socket, lsocket_node))
    grph.add((lsocket_node, pc.property_socket_end, rsocket_node))


def AddInfo(grph, node, entity_ids_arr):
    nam_config = entity_ids_arr[0]
    nam_connection = entity_ids_arr[1]

    AddSockets(grph, node, nam_connection)

    # Then add the manager node.
    node_manager = survol_rabbitmq_manager.MakeUri(nam_config)

    # Inverted property for nicer display.
    grph.add((node, lib_common.MakeProp("Configuration manager"), node_manager))
