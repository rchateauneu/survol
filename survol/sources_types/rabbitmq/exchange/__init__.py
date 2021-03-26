"""
RabbitMQ exchange
"""

import lib_common


def Graphic_colorbg():
    return "#CCCC66"


def EntityOntology():
    return (["Url", "VHost", "Exchange"],)


def MakeUri(url_name, vhost_name, exchange_name):
    vhost_name = vhost_name.lower() # RFC4343
    return lib_common.gUriGen.UriMakeFromDict(
        "rabbitmq/exchange", {"Url": url_name, "VHost": vhost_name, "Exchange": exchange_name})


def EntityName(entity_ids_arr):
    return entity_ids_arr[0] + "/" + entity_ids_arr[1] + "/" + entity_ids_arr[2]
