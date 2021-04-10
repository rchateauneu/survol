"""
Mysql query
"""

from sources_types.sql import query as sql_query_module

from sources_types.mysql import table as mysql_table
from sources_types import mysql as survol_mysql
from sources_types.mysql import instance as survol_mysql_instance

import lib_common


# We do not know if CIM_Process.EntityOntology() is available.
def EntityOntology():
    return (["Query", "Instance",],)


# The SQL query is encoded in base 64 because it contains many special characters which would be too complicated to
# encode as HTML entities. This is not visible as EntityName() does the reverse decoding.
def MakeUri(str_query, instance_name):
    return sql_query_module.MakeUri(str_query, "mysql/query", Instance=instance_name)


# TODO: Ce serait mieux de passer un dictionnaire plutot qu un tableau.
def AddInfo(grph,node, entity_ids_arr):
    instance_name = entity_ids_arr[1]
    node_instance = survol_mysql_instance.MakeUri(instance_name)
    grph.add((node, lib_common.MakeProp("Instance"), node_instance))


# It receives a query and the list of tables or views it depends on,
# and also the connection parameters to the database, which here is only a mysql instance,
# which is a host name, or a host followed by the port number, separated by a colon:
# This must return a list of nodes to be displayed, or None.
# For the moment, we assume that these are all table names, without checking.
# TODO: Find a quick way to check if these are tables or views.
# TODO: This is not tested.
# FIXME: This is not tested.
def QueryToNodesList(connectionKW, list_of_tables, defaultSchemaName=None):
    nodes_list = []
    for tab_nam in list_of_tables:
        tmp_node = mysql_table.MakeUri(connectionKW["Instance"], tab_nam)
        nodes_list.append(tmp_node)
    return nodes_list


def EntityName(entity_ids_arr):
    sql_query = entity_ids_arr[0]
    instance_name = entity_ids_arr[1]
    return sql_query_module.EntityNameUtil("Instance " + instance_name, sql_query)

