#!/usr/bin/python

"""
Tables dependencies in SQL query
"""

import lib_common
import lib_util
import lib_sql
from sources_types import sql
from sources_types.sql import query as sql_query
from sources_types.sql import sheet

# Practically I do not think it will ever be used except as a "base class".

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

	nodeSqlQuery = sql_query.MakeUri(sqlQuery)

	propSheetToQuery = lib_common.MakeProp("Table dependency")

	list_of_tables = lib_sql.TableDependencies(sqlQuery)

	# Based on the pid and the filnam, find which database connection it is.


	for tabNam in list_of_tables:
		nodTab = sheet.MakeUri(tabNam)

		grph.add( ( nodeSqlQuery, propSheetToQuery, nodTab ) )

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()


