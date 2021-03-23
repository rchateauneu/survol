"""
MySql table
"""

import lib_uris
import lib_common
from sources_types import mysql as survol_mysql
from sources_types.mysql import instance as survol_mysql_instance
from sources_types.mysql import database as survol_mysql_database

def EntityOntology():
    return (["Instance","Database","Table",],)


def MakeUri(instance_name, db_name, table_name):
    return lib_uris.gUriGen.UriMakeFromDict(
                                            "mysql/table",
                                            {"Instance": instance_name, "Database": db_name, "Table": table_name})


def EntityName(entity_ids_arr):
    return entity_ids_arr[1] + "." + entity_ids_arr[2] + "@" + entity_ids_arr[0]


def AddInfo(grph, node, entity_ids_arr):
    instance_my_sql = entity_ids_arr[0]
    database_name = entity_ids_arr[1]
    node_instance = survol_mysql_instance.MakeUri(instance_my_sql)
    node_database = survol_mysql_database.MakeUri(instance_my_sql, database_name)
    grph.add((node,lib_common.MakeProp("Instance"), node_instance))
    grph.add((node,lib_common.MakeProp("Database"), node_database))
