#!/usr/bin/python

"""
Tables dependencies in a Sqlite query
"""

import lib_common
import lib_sql
from sources_types.sql import query as sql_query
from sources_types.sqlite import query as sqlite_query

def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	sqlQuery = sql_query.GetEnvArgs(cgiEnv)
	filNam = cgiEnv.m_entity_id_dict["File"]

	nodeSqlQuery = sqlite_query.MakeUri(sqlQuery,filNam)

	propSheetToQuery = lib_common.MakeProp("Table dependency")

	list_of_table_names = lib_sql.TableDependencies(sqlQuery)

	list_of_nodes = sqlite_query.QueryToNodesList(sqlQuery,{"File":filNam },list_of_table_names)

	for nodTab in list_of_nodes:
		grph.add( ( nodeSqlQuery, propSheetToQuery, nodTab ) )

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()


