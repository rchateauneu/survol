"""
RabbitMQ user
"""

import lib_uris


def Graphic_colorbg():
    return "#CC3366"


def EntityOntology():
    return (["Url", "User"],)


def MakeUri(url_name, user_name):
    return lib_uris.gUriGen.node_from_dict("rabbitmq/user", {"Url": url_name, "User": user_name})


def EntityName(entity_ids_arr):
    return entity_ids_arr[0] + "/" + entity_ids_arr[1]
