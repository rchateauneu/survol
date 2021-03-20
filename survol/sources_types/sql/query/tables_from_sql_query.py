#!/usr/bin/env python

"""
Tables dependencies in SQL query
"""

import lib_common
import lib_util
import lib_sql
from sources_types import sql
from sources_types.sql import query as sql_query
from sources_types.sql import sheet

# Maybe not used except as a "base class".


def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    grph = cgiEnv.GetGraph()

    #pidNum = cgiEnv.m_entity_id_dict["Pid"]
    #filNam = cgiEnv.m_entity_id_dict["File"]
    #sqlQuery_encode = cgiEnv.m_entity_id_dict["Query"]

    # sqlQuery_encode = cgiEnv.GetId()
    # TODO: This should be packaged in sql/__init__.py.
    #the_sql_query = lib_util.Base64Decode(sqlQuery_encode)

    the_sql_query = sql_query.GetEnvArgs(cgiEnv)

    node_sql_query = sql_query.MakeUri(the_sql_query)

    prop_sheet_to_query = lib_common.MakeProp("Table dependency")

    list_of_tables = lib_sql.TableDependencies(the_sql_query)

    # Based on the pid and the filnam, find which database connection it is.
    for tab_nam in list_of_tables:
        nod_tab = sheet.MakeUri(tab_nam)

        grph.add((node_sql_query, prop_sheet_to_query, nod_tab))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()


