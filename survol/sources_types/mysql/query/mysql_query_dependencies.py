#!/usr/bin/env python

"""
Tables dependencies in a Sqlite query
"""

import lib_common
import lib_sql
from sources_types.sql import query as sql_query
from sources_types.sqlite import query as sqlite_query

def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    grph = cgiEnv.GetGraph()

    sql_query = sql_query.GetEnvArgs(cgiEnv)
    fil_nam = cgiEnv.m_entity_id_dict["File"]

    node_sql_query = sqlite_query.MakeUri(sql_query,fil_nam)

    prop_sheet_to_query = lib_common.MakeProp("Table dependency")

    list_of_table_names = lib_sql.TableDependencies(sql_query)

    list_of_nodes = sqlite_query.QueryToNodesList(sql_query, {"File": fil_nam}, list_of_table_names)

    for nod_tab in list_of_nodes:
        grph.add((node_sql_query, prop_sheet_to_query, nod_tab))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()


