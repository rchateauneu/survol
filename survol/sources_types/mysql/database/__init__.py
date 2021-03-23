"""
MySql database
"""

import lib_common
from sources_types import mysql as survol_mysql
from sources_types.mysql import instance as survol_mysql_instance


def EntityOntology():
    return (["Instance", "Database", ],)


def MakeUri(instance_name, db_name):
    return lib_common.gUriGen.UriMakeFromDict("mysql/database", {"Instance": instance_name, "Database" : db_name})


def EntityName(entity_ids_arr):
    return entity_ids_arr[1] + "@" + entity_ids_arr[0]


def AddInfo(grph, node, entity_ids_arr):
    instance_my_sql = entity_ids_arr[0]
    node_instance = survol_mysql_instance.MakeUri(instance_my_sql)
    grph.add((node, lib_common.MakeProp("Instance"), node_instance))

