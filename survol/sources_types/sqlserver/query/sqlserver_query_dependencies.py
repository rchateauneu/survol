#!/usr/bin/env python

"""
Tables dependencies in SQLServer query
"""

import lib_common
import lib_util
import lib_sql
from sources_types import sql
from sources_types.sql import query as sql_query
from sources_types.sqlserver import query as sqlserver_query
from sources_types.odbc import dsn as survol_odbc_dsn

def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	#pidNum = cgiEnv.m_entity_id_dict["Pid"]
	#filNam = cgiEnv.m_entity_id_dict["File"]
	#sqlQuery_encode = cgiEnv.m_entity_id_dict["Query"]

	# sqlQuery_encode = cgiEnv.GetId()
	# TODO: This should be packaged in sql/__init__.py.
	#sqlQuery = lib_util.Base64Decode(sqlQuery_encode)

	sqlQuery = sql_query.GetEnvArgs(cgiEnv)
	dsnNam = survol_odbc_dsn.GetDsnNameFromCgi(cgiEnv)

	nodeSqlQuery = sqlserver_query.MakeUri(sqlQuery,dsnNam)

	propSheetToQuery = lib_common.MakeProp("Table dependency")

	list_of_table_names = lib_sql.TableDependencies(sqlQuery)

	# Based on the pid and the filnam, find which database connection it is.

	# What is the schema ??
	list_of_nodes = sqlserver_query.QueryToNodesList(sqlQuery,{"Dsn":dsnNam },list_of_table_names,dsnNam+":SqlServerSchema")

	for nodTab in list_of_nodes:
		grph.add( ( nodeSqlQuery, propSheetToQuery, nodTab ) )

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()


