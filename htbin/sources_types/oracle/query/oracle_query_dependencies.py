#!/usr/bin/python

"""
Tables dependencies in an Oracle query
"""

import lib_common
import rdflib
import lib_sql
from sources_types.sql import query as sql_query
from sources_types.oracle import query as oracle_query

def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = rdflib.Graph()

	sqlQuery = sql_query.GetEnvArgs(cgiEnv)
	dbNam = cgiEnv.m_entity_id_dict["Db"]

	nodeSqlQuery = oracle_query.MakeUri(sqlQuery,dbNam)

	propSheetToQuery = lib_common.MakeProp("Table dependency")

	list_of_table_names = lib_sql.TableDependencies(sqlQuery)

	list_of_nodes = oracle_query.QueryToNodesList(sqlQuery,{"Db":dbNam },list_of_table_names)

	for nodTab in list_of_nodes:
		grph.add( ( nodeSqlQuery, propSheetToQuery, nodTab ) )

	cgiEnv.OutCgiRdf(grph )

if __name__ == '__main__':
	Main()


