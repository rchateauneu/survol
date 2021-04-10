#!/usr/bin/env python

"""
Tables dependencies in an Oracle query
"""

import lib_oracle
import lib_common
import lib_sql
from sources_types.sql import query as sql_query_module
from sources_types.oracle import query as oracle_query


def Main():
    cgiEnv = lib_oracle.OracleEnv()

    grph = cgiEnv.GetGraph()

    sql_query = sql_query_module.GetEnvArgs(cgiEnv)
    db_nam = cgiEnv.m_entity_id_dict["Db"]

    # This is simply the user.
    ora_schema = cgiEnv.OracleSchema()

    node_sql_query = oracle_query.MakeUri(sql_query, db_nam)

    prop_sheet_to_query = lib_common.MakeProp("Table dependency")

    list_of_table_names = lib_sql.TableDependencies(sql_query)

    list_of_nodes = oracle_query.QueryToNodesList({"Db": db_nam}, list_of_table_names, ora_schema)

    for nod_tab in list_of_nodes:
        grph.add((node_sql_query, prop_sheet_to_query, nod_tab))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()


