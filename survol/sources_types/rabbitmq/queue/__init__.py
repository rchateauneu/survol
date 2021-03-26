"""
RabbitMQ queue
"""

import lib_uris
import lib_common
from sources_types.rabbitmq import manager as survol_rabbitmq_manager
from sources_types.rabbitmq import vhost as survol_rabbitmq_vhost


def Graphic_colorbg():
    return "#CCCC66"


def EntityOntology():
    return (["Url", "VHost", "Queue"],)


def MakeUri(url_name, vhost_name, queue_name):
    vhost_name = vhost_name.lower() # RFC4343
    return lib_uris.gUriGen.UriMakeFromDict(
        "rabbitmq/queue", {"Url": url_name, "VHost": vhost_name, "Queue": queue_name})


def EntityName(entity_ids_arr):
    return entity_ids_arr[0] + "/" + entity_ids_arr[1] + "/" + entity_ids_arr[2]


def AddInfo(grph, node, entity_ids_arr):
    nam_config = entity_ids_arr[0]
    nam_v_host = entity_ids_arr[1]

    node_manager = survol_rabbitmq_manager.MakeUri(nam_config)

    nod_v_host = survol_rabbitmq_vhost.MakeUri(nam_config, nam_v_host)
    grph.add((node_manager, lib_common.MakeProp("virtual host node"), nod_v_host))

    grph.add((node, lib_common.MakeProp("Manager"), node_manager))
    grph.add((node, lib_common.MakeProp("Virtual host"), nod_v_host))
