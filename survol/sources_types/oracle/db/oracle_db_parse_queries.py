#!/usr/bin/python

"""
Oracle running queries
"""

# select username,process,server,program,osuser,schemaname from v$session;
# http://stackoverflow.com/questions/199508/how-do-i-show-running-processes-in-oracle-db

import sys
import lib_common
import lib_oracle
import lib_credentials
from sources_types.oracle import query as oracle_query
from sources_types.oracle import db as oracle_db

class OraCallbackParseQry:
	def __init__(self,grph,database_name, propSqlQuery):
		self.m_grph = grph
		self.m_database_name = database_name
		self.m_node_oradb = oracle_db.MakeUri( database_name )
		self.m_propSqlQuery = propSqlQuery

	def oracallback(self,row):
		# Beware that V$SQL.SQL_TEXT is VARCHAR2(1000)
		sql_text = row[3]

		if sql_text == None:
			return

		# TODO: Seems that sql_fulltext not empty only if overflow of sql_text.
		if len(sql_text) == 1000:
			sql_text = str(row[4])

		sys.stderr.write("self.m_database=%s sql_text=%s\n" % (self.m_database_name,sql_text))

		# Mais c est absurde car ici on connait la base de donnees et le schema, et donc
		# on sait quelle est la nature des dependances. Donc on doit generer
		# non pas des "sql/sheet" mais des "oracle/table", "oracle/view" ou "oracle/synonym".
		# Ou alors:
		# entity.py?type=sql/entity?id="select ..."&bdtype=oracle&bd=xe
		# entity.py?type=sql/entity?id="select ..."&bdtype=sqlserver&dsn=MySqlServer
		# ... ou bien pas de bdtype si ca vient d un fichier.
		# On sort donc de notre modele en ajoutant des mots-clefs libres.
		# C est a dire que quand on va cliquer sur cet URI (query + autre chose),
		# on va avoir un script commun (Les dependances, mais les tables meritent un traitement particulier),
		# et eventuellement des scripts specifiques.

		nodeSqlQuery = oracle_query.MakeUri(sql_text, self.m_database_name)

		self.m_grph.add( ( self.m_node_oradb, self.m_propSqlQuery, nodeSqlQuery ) )



def Main():
	cgiEnv = lib_oracle.OracleEnv()
	# cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	# database = cgiEnv.GetId()
	database = cgiEnv.m_oraDatabase

	(oraUser, oraPwd) = lib_credentials.GetCredentials( "Oracle", database )

	conn_str = oraUser + "/" + oraPwd + "@" + database

        # The Oracle user needs: grant select any dictionary to <user>;
	qrySelect = """
	SELECT sess.status, sess.username, sess.schemaname, sql.sql_text,sql.sql_fulltext,proc.spid
	  FROM v$session sess,
		   v$sql     sql,
		   v$process proc
	 WHERE sql.sql_id(+) = sess.sql_id
	   AND sess.type     = 'USER'
	   and sess.paddr = proc.addr
	"""

	propSqlQuery = lib_common.MakeProp("SQL query")

	oraParser = OraCallbackParseQry(grph,database, propSqlQuery)

	# This calls the callback for each retrieved row.
	try:
		lib_oracle.CallbackQuery( conn_str,qrySelect, oraParser.oracallback)
	except:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("CallbackQuery exception:%s in %s"% ( str(exc), qrySelect ) )

	cgiEnv.OutCgiRdf( "LAYOUT_RECT", [propSqlQuery] )


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


