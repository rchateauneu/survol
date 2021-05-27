"""
Sqlserver query
"""

from sources_types.sql import query as sql_query_module
from sources_types.sqlserver import dsn as sqlserver_dsn
from sources_types.sqlserver import table as sqlserver_table
from sources_types.sqlserver import view as sqlserver_view

import sys
import logging
import lib_util
import lib_common

# TODO: What is annoying in this model is, sometimes directories have their own ontology,
# TODO: and sometimes not. What is the rule ? There is no rule, except that: Objects
# TODO: are what is instantiated with a path of subdirectories.


# The result should be ["Query","Dsn"]
# We do not know if CIM_Process.EntityOntology() is available.
def EntityOntology():
    logging.debug("sql_query_module.CgiPropertyQuery()=%s", str(sql_query_module.CgiPropertyQuery()))
    return ([sql_query_module.CgiPropertyQuery(),"Dsn"],)


# The SQL query is encoded in base 64 because it contains many special characters which would be too complicated to
# encode as HTML entities. This is not visible as EntityName() does the reverse decoding.
def MakeUri(str_query, the_dsn):
    # TODO: The right thing todo ?
    return sql_query_module.MakeUri(str_query, "sqlserver/query", Dsn=the_dsn)


def AddInfo(grph, node, entity_ids_arr):
    # strQuery = entity_ids_arr[0]
    the_dsn = entity_ids_arr[1]
    node_dsn = sqlserver_dsn.MakeUri(the_dsn)
    grph.add((node, lib_common.MakeProp("Dsn"), node_dsn))


# This function must have the same signature for all databases.
# For the moment, we assume that these are all table names, without checking.
# TODO: Find a quick way to check if these are tables or views.
def QueryToNodesList(connection_kw, list_of_tables, default_schema_name=None):
    nodes_list = []
    if not default_schema_name:
        default_schema_name = "SqlServerDefaultSchema"
    for tab_nam in list_of_tables:
        logging.debug("tab_nam=%s", tab_nam)
        splt_tab_nam = tab_nam.split(".")
        if len(splt_tab_nam) == 2:
            schema_name = splt_tab_nam[0]
            table_name_no_schema = splt_tab_nam[1]
        else:
            schema_name = default_schema_name
            table_name_no_schema = tab_nam
        tmp_node = sqlserver_table.MakeUri(connection_kw["Dsn"], schema_name, table_name_no_schema)
        nodes_list.append(tmp_node)
    return nodes_list


def EntityName(entity_ids_arr):
    logging.debug("EntityName entity_ids_arr=%s", str(entity_ids_arr))
    sql_query = entity_ids_arr[0]
    dsn_nam = entity_ids_arr[1]
    return sql_query_module.EntityNameUtil("Database " + dsn_nam, sql_query)
