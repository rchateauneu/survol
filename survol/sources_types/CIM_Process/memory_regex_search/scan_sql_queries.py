#!/usr/bin/env python

"""
Extract SQL queries from process heap memory
"""

# It scans a process heap memory to detect SQL queries.
# TODO: It should also search in the executable file itself.
#
# TODO: Check the database libraries we are linked with: It might give a hint
# TODO: of the actual database these queries are executing in.
# TODO: Maybe check the sockets of the process.
# Maybe specific connection strings.
# See: ctypes_scanner.py

import re
import sys
import lib_sql
import lib_util
import lib_common

from sources_types.CIM_Process import memory_regex_search
# from sources_types.sql import query as sql_query
from sources_types.CIM_Process import embedded_sql_query

SlowScript = True


# When scanning the memory of a running process,
# it sometimes returns odd strings separated by "ZZZZ"* sequences.
# "SELECT id FROM moz_favicons WHERE url = ZZZZZZZZSELECT id FROM moz_historyvisits vZZZZZZZZZZZZZZSELECT id FROM moz_historyvisits vZZZZZZZZZZ"
# or also:
# "SELECT f.id FROM moz_favicons f"
# "SELECT f.id FROM moz_favicons fZ"
# or also:
# "sqlQry=SELECT b.id, b.guid from moz_bookmarks b WHERE b.id = ======ZZZZ"
# The noise chars are apparently variable.
#
# And the same string appears several times, possibly because of string manipulation in the heap,
# and temporary variables.
# TODO: This code be a good indication of useless object copies in memory.
#
# Beware of the side effect of scanning firefox memory which contains previous execution.
def _process_scanned_sql_query(raw_sql_query, queries_set):
	#sys.stderr.write("sqlQry=%s\n"%sqlQry)

	# Reasonably, at least three "Z": This is a rule-of-thumb.
	all_qrys = re.split(b"ZZZ*", raw_sql_query)

	for one_qry in all_qrys:
		one_qry.strip()
		#sys.stderr.write("       one_qry=%s\n"%one_qry)
		# Remove the last chars if they are identical and repeated several times.
		len_qry = len(one_qry)
		if len_qry < 10: # Too short to be a SQL query
			continue

		queries_set.add(one_qry)


def _generate_from_sql_queries(grph, node_process, regex_predicate, queries_set, pid_as_integer):
	for one_qry in queries_set:
		try:
			# TODO: The query must come with the PID, so later we can find which database connection it is.
			node_sql_query = embedded_sql_query.MakeUri(one_qry, pid_as_integer)
			grph.add((node_process, regex_predicate, node_sql_query))
		except Exception as exc:
			grph.add((node_process, regex_predicate, lib_util.NodeLiteral("_generate_from_sql_queries:" + str(exc))))


# TODO: What is annoying is that it is in a sub-directory, but it does not have
# TODO: a specific ontology etc ...
def Main():
	cgiEnv = lib_common.ScriptEnvironment()
	pid_as_integer = int(cgiEnv.GetId())

	grph = cgiEnv.GetGraph()

	node_process = lib_common.gUriGen.PidUri(pid_as_integer)

	dict_regex_sql = lib_sql.SqlRegularExpressions()

	arr_props = []

	# TODO: Unfortunately it scans several times the memory process.
	for rgx_key in dict_regex_sql:
		rgx_sql = dict_regex_sql[rgx_key]
		regex_predicate = lib_common.MakeProp(rgx_key)
		arr_props.append(regex_predicate)

		try:
			# https://docs.python.org/3/library/re.html
			# re.MULTILINE | re.ASCII | re.IGNORECASE
			matched_sqls = memory_regex_search.GetRegexMatches(pid_as_integer, rgx_sql, re.IGNORECASE)
		except Exception as exc:
			lib_common.ErrorMessageHtml("Error:%s. Protection ?" % str(exc))

		all_queries_set = set()

		for sql_idx in matched_sqls:
			sql_qry = matched_sqls[sql_idx]
			_process_scanned_sql_query(sql_qry, all_queries_set)

		_generate_from_sql_queries(grph, node_process, regex_predicate, all_queries_set, pid_as_integer)

	cgiEnv.OutCgiRdf("LAYOUT_RECT",arr_props)

if __name__ == '__main__':
	Main()

