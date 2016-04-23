#!/usr/bin/python

import re
import lib_common
from lib_properties import pc
import rdflib
import lib_oracle
import lib_credentials

#  NOT DONE YET: THIS PARSES SQL QUERIES AND EXTRACTS THE TABLES
# THE PARSING WORKS-ISH BUT THIS IS NOT INTEGRATED IN THE 
# FRAMEWORK.
# THIS CAN BE RELATED TO A OS PROCESS ...
# ... OR AN ORACLE SESSION.
# THEREFORE IT HAS TO GO TO A LIBRARY.

# Returns the index of the end of the sub-expression, that is,
# the position of the first closing parentheses which is not opened here.
def closing_parenthesis(stri,func = None):
	nb_par = 0
	quoted_simple = False
	quoted_double = False
	escaped = False
	for idx in range( len(stri) ):
		ch = stri[idx]

		if ch == '\\':
			escaped = True
			continue

		if escaped:
			escaped = False
			continue

		if ch == "'":
			quoted_simple = not quoted_simple
			continue

		if quoted_simple:
			continue
			
		if ch == '"':
			quoted_double = not quoted_double
			continue
		
		if quoted_double:
			continue

		if ch == '(':
			nb_par += 1
		elif ch == ')':
			if nb_par == 0:
				return idx
			else:
				nb_par -= 1
				
		if func != None:
			if func( stri, idx ):
				return idx
	return len
	
def table_dependency( table ):
	print("DEPENDS="+ table)
	
schema_rgx = "[A-Za-z_][A-Za-z0-9_$-]*"
table_rgx = "[A-Za-z_][A-Za-z0-9_$-]*"
syno_rgx = "[A-Za-z_][A-Za-z0-9_-]*"
where_rgx = '\s+WHERE'
schema_table_rgx = schema_rgx + '\.' + table_rgx


# TODO: Should probably start by splitting based on UNION, INTERSECT etc...
# Anyway the syntax is really complicated.
def parse_sql_subselect(select_tables_txt):
	print("\nSubselect="+select_tables_txt)
	remtch_subselect = re.match( '^\(\s*SELECT\s+(.*)', select_tables_txt, re.IGNORECASE )
	if not remtch_subselect:
		# If no parenthese, maybe this is a simple table.
		print("Simple select="+select_tables_txt)
		return parse_sql_select(select_tables_txt)

	rest_select = remtch_subselect.group(1)
	closing_par = closing_parenthesis( rest_select )
	print("closing_par="+str(closing_par)+ " len="+str(len(rest_select) ))
	
	subq = rest_select[ : closing_par ]
	print("\nsubq="+subq)
	if not parse_sql_select( subq ):
		return False
		
	subqs_rest_comma = rest_select[ closing_par + 1 : ]
	print("\nsubqs_rest_comma="+subqs_rest_comma)
	
	# Now maybe there is a synonym and a parenthesis.
	remtch_suite = re.match('^\s*' + syno_rgx + '\s*,\s*(.*)', subqs_rest_comma, re.IGNORECASE )
	if remtch_suite:
		subqs_rest = remtch_suite.group(1)
	else:
		remtch_suite = re.match('^\s*,\s*(.*)', subqs_rest_comma, re.IGNORECASE )
		if remtch_suite:
			subqs_rest = remtch_suite.group(1)
		else:
			# Maybe end of subselect ?
			remtch_suite = re.match('^\s*' + syno_rgx , subqs_rest_comma, re.IGNORECASE )
			if remtch_suite:
				return True
			remtch_suite = re.match('^\s*', subqs_rest_comma, re.IGNORECASE )
			if remtch_suite:
				return True
			return False
	
	print("\nsubqs_rest="+subqs_rest)

	remtch_union = re.match( '^\s*UNION\s+(.*)', subqs_rest, re.IGNORECASE )
	if remtch_union:
		if not parse_sql_select( remtch_union.group(1) ):
			return False
		return True
	
	remtch_intersect = re.match( '^\s*INTERSECT\s+(.*)', subqs_rest, re.IGNORECASE )
	if remtch_intersect:
		if not parse_sql_select( remtch_intersect.group(1) ):
			return False
		return True
	
	print("Recursive subselect="+subqs_rest)

	return parse_sql_subselect(subqs_rest)
	
# To extract the first table of the tables list in a SELECT statement.
regex_select_tabs_list = (
	'^(' + schema_table_rgx + ')\s+' + syno_rgx + where_rgx,
	'^(' + table_rgx + ')\s+' + syno_rgx + where_rgx,
	'^(' + schema_table_rgx + ')' + where_rgx,
	'^(' + table_rgx + ')' + where_rgx,
	'^(' + schema_table_rgx + ')\s+' + syno_rgx + '(.*)',
	'^(' + table_rgx + ')\s+' + syno_rgx + '(.*)',
	'^(' + schema_table_rgx + ')(.*)',
	'^(' + table_rgx + ')(.*)'
)

def parse_sql_select(rest_select):
	print("parse_sql_select:"+rest_select)
	from_finder = lambda stri, idx: stri[ idx:idx + 5 ].upper() == "FROM "
	idx_from = closing_parenthesis( rest_select, from_finder )
	if idx_from == len(rest_select):
		print("parse_sql_select bad:"+rest_select)
		return False
	# After "FROM"
	select_tables_txt = rest_select[ idx_from + 5: ]
		
	while select_tables_txt != "":
		print("select_tables_txt=[" + select_tables_txt + "]")
		for regex_select_table in regex_select_tabs_list:
			remtch_select_table = re.match( regex_select_table, select_tables_txt, re.IGNORECASE )
			if remtch_select_table:
				break

		if remtch_select_table:
			table_dependency( remtch_select_table.group(1) )
			try:
				select_tables_txt = remtch_select_table.group(2).lstrip( " \t," )
			except IndexError:
				# Maybe we have matched the regex which indicates the end of the tables list.
				select_tables_txt = ""
		else:
			# Maybe a sub-query.
			print("SubQuery:"+select_tables_txt)
			if not parse_sql_subselect(select_tables_txt):
				print("UNKNOWN")
				return False
			# We can end because parse_sql_subselect calls itself.
			# In fact parse_sql_subselect() is enough.
			# TODO: Simplify that.
			select_tables_txt = ""
			
	return True
	
	
# Gets a SQL query and extracts the tables it depends on.
def parse_sql(sql_text):
	sql_text = sql_text.lstrip( " \t" )

	# This is a stored procedure, we do not process them yet,
	# although it is possible.
	remtch_begin = re.match( '^BEGIN .*', sql_text, re.IGNORECASE )
	if remtch_begin:
		return True
		
	remtch_declare = re.match( '^DECLARE .*', sql_text, re.IGNORECASE )
	if remtch_declare:
		return True
		
	# Queries are parsed, but this does not cover all cases.
	# This assumes that queries are normalised: Uppercases, spaces etc...
	remtch_insert = re.match( '^INSERT INTO ([^ ]*)', sql_text, re.IGNORECASE )
	if remtch_insert:
		table_dependency( remtch_insert.group(1) )
		# TODO: The inserted value might be a sub-query.
		return True
		
	remtch_delete = re.match( '^DELETE FROM ([^ ]*)', sql_text, re.IGNORECASE )
	if remtch_delete:
		table_dependency( remtch_delete.group(1) )
		return True
		
	remtch_update = re.match( '^UPDATE ([^ ]*)', sql_text, re.IGNORECASE )
	if remtch_update:
		table_dependency( remtch_update.group(1) )
		return True
	
	# FIXME: This will match the last "FROM" even if this is in a sub-query.
	remtch_select = re.match( '^SELECT +(.*)', sql_text, re.IGNORECASE )
	if remtch_select:
		if parse_sql_select( remtch_select.group(1) ):
			return True

	remtch_with = re.match( '^WITH ' + table_rgx + ' AS \((.*)', sql_text, re.IGNORECASE )
	if remtch_with:
		rest_with = remtch_with.group(1)
		closing_par = closing_parenthesis( rest_with )
		
		subqA = rest_with[ : closing_par ]

		# It can only be a SELECT, this is a sub-query, and explicitly mentioned in the regex.
		print("\nSubQ1=" + subqA )
	
		if not parse_sql( subqA ):
			return False

		# Probably a SELECT, not sure of what WITH accepts as query.
		subqB = rest_with[ closing_par + 1 : ]
		print("\nSubQ2=" + subqB )
		if not parse_sql( subqB ):
			return False
		return True
		
	return False
 
def oracallback(row):
	# Beware that V$SQL.SQL_TEXT is VARCHAR2(1000)
	sql_text = row[3]

	if sql_text == None:
		return

	# Seems that sql_fulltext not empty only if overflow of sql_text.
	if len(sql_text) == 1000:
		sql_text = str(row[4])
	
	print("\nSql="+str(len(sql_text))+":"+sql_text)
	
	if not parse_sql(sql_text):
		print("Caramba !!")
		print( row[0], "-", row[1], "-", row[2], "-", sql_text, "-", row[5] )
		exit(1)

def Main():
	cgiEnv = lib_common.CgiEnv(
		"Oracle tables",
		lib_oracle.logo )

	grph = rdflib.Graph()

	database = cgiEnv.GetId()

	(oraUser, oraPwd) = lib_credentials.GetCredentials( "Oracle", database )

	conn_str = oraUser + "/" + oraPwd + "@" + database






	sql_query = """
	SELECT sess.status, sess.username, sess.schemaname, sql.sql_text,sql.sql_fulltext,proc.spid
	  FROM v$session sess,
		   v$sql     sql,
		   v$process proc
	 WHERE sql.sql_id(+) = sess.sql_id
	   AND sess.type     = 'USER'
	   and sess.paddr = proc.addr
	"""

	# for row in lib_oracle.ExecuteQuery( conn_str,sql_query):
	lib_oracle.CallbackQuery( conn_str,sql_query, oracallback)

# FIXME: THIS MUST SHOW THE SCHEMA WHICH MUST BE ADDED.

#Sql=255: SELECT sess.status, sess.username, sess.schemaname, sql.sql_text,sql.sql_fulltext,proc.spid   FROM v$session sess,        v$sql     sql,        v$process proc  WHERE sql.sql_id(+) = sess.sql_id    AND sess.type     = 'USER'    and sess.paddr = proc.addr
#parse_sql_select:sess.status, sess.username, sess.schemaname, sql.sql_text,sql.sql_fulltext,proc.spid   FROM v$session sess,        v$sql     sql,        v$process proc  WHERE sql.sql_id(+) = sess.sql_id    AND sess.type     = 'USER'    and sess.paddr = proc.addr
#select_tables_txt=[v$session sess,        v$sql     sql,        v$process proc  WHERE sql.sql_id(+) = sess.sql_id    AND sess.type     = 'USER'    and sess.paddr = proc.addr ]
#DEPENDS=v$session
#select_tables_txt=[v$sql     sql,        v$process proc  WHERE sql.sql_id(+) = sess.sql_id    AND sess.type     = 'USER'    and sess.paddr = proc.addr ]
#DEPENDS=v$sql
#select_tables_txt=[v$process proc  WHERE sql.sql_id(+) = sess.sql_id    AND sess.type     = 'USER'    and sess.paddr = proc.addr ]
#DEPENDS=v$process

if __name__ == '__main__':
	Main()


