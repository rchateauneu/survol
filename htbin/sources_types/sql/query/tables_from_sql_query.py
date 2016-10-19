#!/usr/bin/python

"""
Tables dependencies in SQL query
"""

import lib_common
import lib_util
#from lib_properties import pc
import rdflib
import lib_sql
from sources_types import sql
from sources_types.sql import query
from sources_types.sql import sheet

def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = rdflib.Graph()

	# There is only one parameter.
	sqlQuery_encode = cgiEnv.GetId()
	# TODO: This should be packaged in lib_symbol.
	sqlQuery = lib_util.Base64Decode(sqlQuery_encode)

	nodeSqlQuery = query.MakeUri(sqlQuery)

	propSheetToQuery = lib_common.MakeProp("Table dependency")

	list_of_tables = lib_sql.TableDependencies(sqlQuery)

	for tabNam in list_of_tables:
		nodTab = sheet.MakeUri(tabNam)

		grph.add( ( nodeSqlQuery, propSheetToQuery, nodTab ) )

	cgiEnv.OutCgiRdf(grph )

if __name__ == '__main__':
	Main()


