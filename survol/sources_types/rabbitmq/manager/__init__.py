"""
RabbitMQ configuration
"""

import lib_common


def Graphic_colorbg():
    return "#FFCC66"


def EntityOntology():
    return (["Url",],)


def MakeUri(url_name):
    # This URL is nothing but a host:port.
    # The host is case-insensitive.
    url_name = url_name.lower()
    return lib_common.gUriGen.UriMakeFromDict("rabbitmq/manager", {"Url": url_name})


def EntityName(entity_ids_arr):
    return entity_ids_arr[0]
