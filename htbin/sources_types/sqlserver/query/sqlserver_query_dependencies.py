#!/usr/bin/python

"""
Tables dependencies in SQLServer query
"""

import lib_common
import lib_util
import rdflib
import lib_sql
from sources_types import sql
from sources_types.sql import query as sql_query
from sources_types.sqlserver import query as sqlserver_query

def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = rdflib.Graph()

	#pidNum = cgiEnv.m_entity_id_dict["Pid"]
	#filNam = cgiEnv.m_entity_id_dict["File"]
	#sqlQuery_encode = cgiEnv.m_entity_id_dict["Query"]

	# sqlQuery_encode = cgiEnv.GetId()
	# TODO: This should be packaged in sql/__init__.py.
	#sqlQuery = lib_util.Base64Decode(sqlQuery_encode)

	sqlQuery = sql_query.GetEnvArgs(cgiEnv)
	dsnNam = cgiEnv.m_entity_id_dict["Dsn"]

	nodeSqlQuery = sqlserver_query.MakeUri(sqlQuery,dsnNam)

	propSheetToQuery = lib_common.MakeProp("Table dependency")

	list_of_table_names = lib_sql.TableDependencies(sqlQuery)

	# Based on the pid and the filnam, find which database connection it is.


	list_of_nodes = sqlserver_query.QueryToNodesList(sqlQuery,{"Dsn":dsnNam },list_of_table_names)

	for nodTab in list_of_nodes:
		grph.add( ( nodeSqlQuery, propSheetToQuery, nodTab ) )

	cgiEnv.OutCgiRdf(grph )

if __name__ == '__main__':
	Main()


