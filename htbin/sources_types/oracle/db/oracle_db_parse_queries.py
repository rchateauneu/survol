#!/usr/bin/python

"""
Oracle running queries
"""

# select username,process,server,program,osuser,schemaname from v$session;
# http://stackoverflow.com/questions/199508/how-do-i-show-running-processes-in-oracle-db

import sys
import lib_common
#from lib_properties import pc
import rdflib
import lib_oracle
import lib_credentials
#import lib_sql
#from sources_types import sql
from sources_types.sql import query
from sources_types.oracle import db as oracle_db

class OraCallbackParseQry:
	def __init__(self,grph,node_oradb, propSqlQuery):
		self.m_grph = grph
		self.m_node_oradb = node_oradb
		self.m_propSqlQuery = propSqlQuery

	def oracallback(self,row):
		# Beware that V$SQL.SQL_TEXT is VARCHAR2(1000)
		sql_text = row[3]

		if sql_text == None:
			return

		# TODO: Seems that sql_fulltext not empty only if overflow of sql_text.
		if len(sql_text) == 1000:
			sql_text = str(row[4])

		sys.stderr.write("sql_text=%s\n" % sql_text)

		# Mais c est absurde car ici on connait la base de donnees et le schema, et donc
		# on sait quelle est la nature des dependances. Donc on doit generer
		# non pas des "sql/sheet" mais des "oracle/table", "oracle/view" ou "oracle/synonym".
		# Ou alors:
		# entity.py?type=sql/entity?id="select ..."&bdtype=oracle&bd=xe
		# entity.py?type=sql/entity?id="select ..."&bdtype=sqlserver&dsn=MySqlServer
		# ... ou bien pas de bdtype si ca vient d un fichier.
		# On sort donc de notre modele en ajoutant des mots-clefs libres.


		nodeSqlQuery = query.MakeUri(sql_text)

		self.m_grph.add( ( self.m_node_oradb, self.m_propSqlQuery, nodeSqlQuery ) )



def Main():
	cgiEnv = lib_oracle.OracleEnv()
	# cgiEnv = lib_common.CgiEnv()

	grph = rdflib.Graph()

	# database = cgiEnv.GetId()
	database = cgiEnv.m_oraDatabase
	node_oradb = oracle_db.MakeUri( database )

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

	propSqlQuery = lib_common.MakeProp("SQL query")

	oraParser = OraCallbackParseQry(grph,node_oradb, propSqlQuery)

	# This calls the callback for each retrieved row.
	lib_oracle.CallbackQuery( conn_str,sql_query, oraParser.oracallback)

	cgiEnv.OutCgiRdf(grph, "LAYOUT_RECT", [propSqlQuery] )


# TODO: FIXME: THIS MUST SHOW THE SCHEMA WHICH MUST BE ADDED.

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


