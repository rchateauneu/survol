#!/usr/bin/python

"""
Tables dependencies in an Oracle query
"""

import lib_oracle
import lib_common
import lib_sql
from sources_types.sql import query as sql_query
from sources_types.oracle import query as oracle_query

def Main():
	# cgiEnv = lib_common.CgiEnv()
	cgiEnv = lib_oracle.OracleEnv()


	grph = cgiEnv.GetGraph()

	sqlQuery = sql_query.GetEnvArgs(cgiEnv)
	dbNam = cgiEnv.m_entity_id_dict["Db"]

	# This is simply the user.
	oraSchema = cgiEnv.OracleSchema()

	nodeSqlQuery = oracle_query.MakeUri(sqlQuery,dbNam)

	propSheetToQuery = lib_common.MakeProp("Table dependency")

	list_of_table_names = lib_sql.TableDependencies(sqlQuery)

	list_of_nodes = oracle_query.QueryToNodesList(sqlQuery,{"Db":dbNam },list_of_table_names,oraSchema)

	for nodTab in list_of_nodes:
		grph.add( ( nodeSqlQuery, propSheetToQuery, nodTab ) )

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()


