#!/usr/bin/env python

"""
Tables dependencies in SQL query
"""

import lib_common
import lib_util
import lib_sql
from sources_types import sql
from sources_types.sql import query as sql_query_module
from sources_types.sql import sheet

# FIXME: This is not tested yet.
# FIXME: The idea is to manipulate a query without a process nor a database.
# FIXME: This would return "abstract" tables and views, syntactically correct but with no connection
# FIXME: to a real database, not any possibilty to know of these are tables and views.
# FIXME: Therefore, the "abstract" type "sql/sheet" represents such an abstract table.


def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    grph = cgiEnv.GetGraph()

    sql_query = cgiEnv.m_entity_id_dict["Query"]

    node_sql_query = sql_query_module.MakeUri(sql_query)

    prop_sheet_to_query = lib_common.MakeProp("Table dependency")

    list_of_tables = lib_sql.TableDependencies(sql_query)

    # Based on the pid and the filnam, find which database connection it is.
    for tab_nam in list_of_tables:
        nod_tab = sheet.MakeUri(tab_nam)

        grph.add((node_sql_query, prop_sheet_to_query, nod_tab))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()


