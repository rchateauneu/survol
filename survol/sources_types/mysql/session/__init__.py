"""
MySql session
"""

import lib_uris
import lib_common
from sources_types import mysql as survol_mysql
from sources_types.mysql import instance as survol_mysql_instance


def EntityOntology():
    return (["Instance", "Id",],)


def MakeUri(instance_name, session_id):
    return lib_uris.gUriGen.node_from_dict("mysql/session", {"Instance": instance_name, "Id": session_id})


def EntityName(entity_ids_arr):
    return "Session:" + entity_ids_arr[1] + "@" + entity_ids_arr[0]


def AddInfo(grph,node, entity_ids_arr):
    instance_my_sql = entity_ids_arr[0]
    node_instance = survol_mysql_instance.MakeUri(instance_my_sql)
    grph.add((node,lib_common.MakeProp("Instance"), node_instance))

