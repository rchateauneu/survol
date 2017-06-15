#!/usr/bin/python

"""
Extract SQL queries from process heap memory
"""

# It cans a process heap memory to detect SQL queries.
# TODO: It should also search in the executable file itself.
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
import lib_common

from sources_types.CIM_Process import memory_regex_search
# from sources_types.sql import query as sql_query
from sources_types.CIM_Process import embedded_sql_query

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
# Beware of the side effect of scanning firefox memory which contains previous execution.
def ProcessScannedSqlQuery(sqlQry, setQrys):
	#sys.stderr.write("sqlQry=%s\n"%sqlQry)

	allQrys = re.split("ZZZ*",sqlQry)

	for oneQry in allQrys:
		oneQry.strip()
		#sys.stderr.write("       oneQry=%s\n"%oneQry)
		# Remove the last chars if they are identical and repeated several times.
		lenQry = len(oneQry)
		if lenQry < 10: # Too short to be a SQL query
			continue

		setQrys.add( oneQry )

def GenerateFromSqlQrys(grph, node_process, rgxProp, setQrys, pidint):
	for oneQry in setQrys:
		try:
			# TODO: The query must come with the PID, so later we can find which database connection it is.
			# nodeSqlQuery = sql_query.MakeUri(oneQry)
			nodeSqlQuery = embedded_sql_query.MakeUri(oneQry,pidint)
			grph.add( ( node_process, rgxProp, nodeSqlQuery ) )

		except Exception:
			exc = sys.exc_info()[1]
			grph.add( ( node_process, rgxProp, rdflib.Literal("GenerateFromSqlQrys:"+str(exc)) ) )

# TODO: What is annoying is that it is in a sub-directory, but it does not have
# TODO: a specific ontology etc ...
def Main():
	cgiEnv = lib_common.CgiEnv()
	pidint = int( cgiEnv.GetId() )

	grph = cgiEnv.GetGraph()

	node_process = lib_common.gUriGen.PidUri(pidint)

	dictRegexSQL = lib_sql.SqlRegularExpressions()

	arrProps = []

	# TODO: Unfortunately it scans several times the memory process.
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

		GenerateFromSqlQrys(grph, node_process, rgxProp, setQrys, pidint)


	cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT",arrProps)

if __name__ == '__main__':
	Main()

