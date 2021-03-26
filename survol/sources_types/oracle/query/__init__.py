"""
Oracle database query
"""

import sys

import lib_uris
import lib_util
import lib_common
from sources_types.sql import query as sql_query_module
from sources_types.oracle import db as oracle_db
from sources_types.oracle import table as oracle_table
from sources_types.oracle import view as oracle_view
from sources_types.oracle import synonym as oracle_synonym


def Graphic_colorbg():
    return "#CC99FF"


def EntityOntology():
    return (["Query", "Db"],)


# The SQL query is encoded in base 64 because it contains many special characters which would be too complicated to
# encode as HTML entities. This is not visible as EntityName() does the reverse decoding.
def MakeUri(str_query, the_db):
    # TODO: We have hard-coded the process definition with "Db".
    # TODO: The entity parameter should be passed differently, more elegant. Not sure.
    return sql_query_module.MakeUri(str_query, "oracle/query", Db=the_db)


# TODO: This should maybe receive a dictionary instead of a list.
def AddInfo(grph,node, entity_ids_arr):
    the_db = entity_ids_arr[1]
    node_db = oracle_db.MakeUri(the_db)
    grph.add((node, lib_common.MakeProp("Db"), node_db))


# For the moment, we assume that these are all table names, without checking.
# TODO: Find a quick way to check if these are tables or views.
def QueryToNodesList(sqlQuery, connection_kw, list_of_tables, default_schema_name=None):
    nodes_list = []
    # This should be taken from the credentials.
    if not default_schema_name:
        default_schema_name = "OracleDefaultSchema"
    for tab_nam in list_of_tables:
        splt_tab_nam = tab_nam.split(".")
        if len(splt_tab_nam) == 2:
            schema_name = splt_tab_nam[0]
            table_name_no_schema = splt_tab_nam[1]
        else:
            schema_name = default_schema_name
            table_name_no_schema = tab_nam
        tmp_node = oracle_table.MakeUri(connection_kw["Db"], schema_name, table_name_no_schema)
        nodes_list.append(tmp_node)
    return nodes_list


# TODO: This produces a nice message but what is also needed is the decoding of the query.
def EntityName(entity_ids_arr):
    sql_query = entity_ids_arr[0]
    db_nam = entity_ids_arr[1]
    return sql_query_module.EntityNameUtil("Database " + db_nam, sql_query)
