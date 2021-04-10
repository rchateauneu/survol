#!/usr/bin/env python

"""
Tables dependencies in SQLServer query
"""

import lib_common
import lib_util
import lib_sql
from sources_types import sql
from sources_types.sql import query as sql_query_module
from sources_types.sqlserver import query as sqlserver_query
from sources_types.odbc import dsn as survol_odbc_dsn


def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    grph = cgiEnv.GetGraph()

    sql_query = sql_query_module.GetEnvArgs(cgiEnv)
    dsn_nam = survol_odbc_dsn.GetDsnNameFromCgi(cgiEnv)

    node_sql_query = sqlserver_query.MakeUri(sql_query, dsn_nam)

    propSheetToQuery = lib_common.MakeProp("Table dependency")

    list_of_table_names = lib_sql.TableDependencies(sql_query)

    # Based on the pid and the filnam, find which database connection it is.

    # What is the schema ??
    list_of_nodes = sqlserver_query.QueryToNodesList(
        {"Dsn": dsn_nam}, list_of_table_names, dsn_nam + ":SqlServerSchema")

    for nod_tab in list_of_nodes:
        grph.add((node_sql_query, propSheetToQuery, nod_tab))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()


