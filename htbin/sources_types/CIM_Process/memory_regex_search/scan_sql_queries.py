#!/usr/bin/python

"""
Extract SQL queries from process heap memory
"""

# Scanner la memoire pour chercher des requetes SQL.
# Mais de quelle BDD ? Oracle ? Odbc ? Sqlite ?
# Utiliser Sqlparse ?
# Successfully installed sqlparse-0.1.19
#
# On ne cherche pas seulement dans le heap mais aussi dans la memoire
# des constantes. Ou alors dans le exe et les dlls ? Autant chercher dans la memoire.
# Il peut y avoir des %s dans les chaines.
# Peut-etre simplement rechercher les chaines de caracteres et filtrer ensuite.
#
# TODO: Check the database libraries we are linked with: It might give a hint
# TODO: of the actual database these queries are executing in.
# TODO: Maybe check the sockets of the process.
# Maybe specific connection strings.
# See: ctypes_scanner.py

import re
import sys
import rdflib
import lib_sql
# import lib_util
import lib_common
#from lib_properties import pc

#from sources_types import CIM_Process
from sources_types.CIM_Process import memory_regex_search
from sources_types.sql import query as sql_query

# We get strange strings separated by "ZZZZ"
# "SELECT id FROM moz_favicons WHERE url = ZZZZZZZZSELECT id FROM moz_historyvisits vZZZZZZZZZZZZZZSELECT id FROM moz_historyvisits vZZZZZZZZZZ"
# or also:
# "SELECT f.id FROM moz_favicons f"
# "SELECT f.id FROM moz_favicons fZ"
# or also:
# "sqlQry=SELECT b.id, b.guid from moz_bookmarks b WHERE b.id = ======ZZZZ"
# The noise chars are apparently variable.
#
# And sometime we have several times the same because of string manipulation in the heap, I guess.
#
#splitZZZ = re.compile("ZZZ*")
#
# Beware of the side effect of scanning firefox memory which contains previous execution.
def ProcessScannedSqlQuery(sqlQry, setQrys):
	#sys.stderr.write("sqlQry=%s\n"%sqlQry)

	# allQrys = sqlQry.split("ZZZ*")
	allQrys = re.split("ZZZ*",sqlQry)
	# allQrys = re.split("ZZZ*",sqlQry)

	for oneQry in allQrys:
		oneQry.strip()
		#sys.stderr.write("       oneQry=%s\n"%oneQry)
		# Remove the last chars if they are identical and repeated several times.
		lenQry = len(oneQry)
		if lenQry < 10: # Too short to be a SQL query
			continue

		setQrys.add( oneQry )

def GenerateFromSqlQrys(grph, node_process, rgxProp, setQrys):
	for oneQry in setQrys:
		try:
			# For the moment, we just print the query.
			# grph.add( ( node_process, pc.property_rdf_data_nolist1, nodePortalWbem ) )

			nodeSqlQuery = sql_query.MakeUri(oneQry)
			# grph.add( ( node_process, rgxProp, rdflib.Literal(oneQry) ) )
			grph.add( ( node_process, rgxProp, nodeSqlQuery ) )


		except Exception:
			exc = sys.exc_info()[1]
			grph.add( ( node_process, rgxProp, rdflib.Literal("XXYYZZ") ) )

def Main():
	cgiEnv = lib_common.CgiEnv()
	pidint = int( cgiEnv.GetId() )

	grph = rdflib.Graph()

	node_process = lib_common.gUriGen.PidUri(pidint)

	dictRegexSQL = lib_sql.SqlRegularExpressions()

	arrProps = []
	for rgxKey in dictRegexSQL:
		rgxSQL = dictRegexSQL[rgxKey]
		rgxProp = lib_common.MakeProp(rgxKey)
		arrProps.append( rgxProp )

		try:
			# https://docs.python.org/3/library/re.html
			# re.MULTILINE | re.ASCII | re.IGNORECASE
			matchedSqls = memory_regex_search.GetRegexMatches(pidint,rgxSQL, re.IGNORECASE)
		except Exception:
			exc = sys.exc_info()[1]
			lib_common.ErrorMessageHtml("Error:%s. Protection ?"%str(exc))

		setQrys = set()

		for sqlQry in matchedSqls:
			ProcessScannedSqlQuery( sqlQry, setQrys)

		GenerateFromSqlQrys(grph, node_process, rgxProp, setQrys)


	cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT",arrProps)

if __name__ == '__main__':
	Main()

