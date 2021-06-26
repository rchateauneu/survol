"""
Sqlite query
"""

import lib_uris
from sources_types.sql import query as sql_query_module
from sources_types.sqlite import table as sqlite_table
from sources_types.sqlite import file as sqlite_file
import lib_common


def Graphic_colorbg():
    return "#FFCC66"


# We do not know if CIM_Process.EntityOntology() is available.
def EntityOntology():
    return (["Query", "File"],)


# The SQL query is encoded in base 64 because it contains many special characters which would be too complicated to
# encode as HTML entities. This is not visible as EntityName() does the reverse decoding.
def MakeUri(str_query, file_name):
    return sql_query_module.MakeUri(str_query, "sqlite/query", File=file_name)


# TODO: This could maybe receive a dictionary instead of a list.
def AddInfo(grph, node, entity_ids_arr):
    file_name = entity_ids_arr[1]
    node_file = lib_uris.gUriGen.FileUri(file_name)
    grph.add((node, lib_common.MakeProp("Path"), node_file))

    db_nod = sqlite_file.MakeUri(file_name)
    grph.add((node, lib_common.MakeProp("Sqlite database"), db_nod))


# It receives a query and the list of tables or views it depends on,
# and also the connection parameters to the database, which here is only a sqlite file.
# This must return a list of nodes to be displayed, or None.
# For the moment, we assume that these are all table names, without checking.
# TODO: Find a quick way to check if these are tables or views.
def QueryToNodesList(connection_kw, list_of_tables, defaultSchemaName=None):
    nodes_list = []
    for tab_nam in list_of_tables:
        tmp_node = sqlite_table.MakeUri(connection_kw["File"], tab_nam)
        nodes_list.append(tmp_node)
    return nodes_list


def EntityName(entity_ids_arr):
    sql_query = entity_ids_arr[0]
    file_name = entity_ids_arr[1]
    return sql_query_module.EntityNameUtil("File " + file_name, sql_query)

