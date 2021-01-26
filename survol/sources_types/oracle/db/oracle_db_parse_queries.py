#!/usr/bin/env python

"""
Oracle running queries
"""

# select username,process,server,program,osuser,schemaname from v$session;
# http://stackoverflow.com/questions/199508/how-do-i-show-running-processes-in-oracle-db

import sys
import logging
import lib_common
import lib_oracle
import lib_credentials
from sources_types.oracle import query as oracle_query
from sources_types.oracle import db as oracle_db


class OraCallbackParseQry:
    def __init__(self, grph, database_name, prop_sql_query):
        self.m_grph = grph
        self.m_database_name = database_name
        self.m_node_oradb = oracle_db.MakeUri(database_name)
        self.m_propSqlQuery = prop_sql_query

    def oracallback(self, row):
        # Beware that V$SQL.SQL_TEXT is VARCHAR2(1000)
        sql_text = row[3]

        if sql_text == None:
            return

        # TODO: Seems that sql_fulltext not empty only if overflow of sql_text.
        if len(sql_text) == 1000:
            sql_text = str(row[4])

        logging.debug("self.m_database=%s sql_text=%s", self.m_database_name, sql_text)

        node_sql_query = oracle_query.MakeUri(sql_text, self.m_database_name)

        self.m_grph.add((self.m_node_oradb, self.m_propSqlQuery, node_sql_query))


def Main():
    cgiEnv = lib_oracle.OracleEnv()
    # cgiEnv = lib_common.CgiEnv()

    grph = cgiEnv.GetGraph()

    database = cgiEnv.m_oraDatabase

    ora_user, ora_pwd = lib_credentials.GetCredentials( "Oracle", database)

    conn_str = ora_user + "/" + ora_pwd + "@" + database

        # The Oracle user needs: grant select any dictionary to <user>;
    qry_select = """
    SELECT sess.status, sess.username, sess.schemaname, sql.sql_text,sql.sql_fulltext,proc.spid
      FROM v$session sess,
           v$sql     sql,
           v$process proc
     WHERE sql.sql_id(+) = sess.sql_id
       AND sess.type     = 'USER'
       and sess.paddr = proc.addr
    """

    prop_sql_query = lib_common.MakeProp("SQL query")

    oraParser = OraCallbackParseQry(grph, database, prop_sql_query)

    # This calls the callback for each retrieved row.
    try:
        lib_oracle.CallbackQuery(conn_str, qry_select, oraParser.oracallback)
    except Exception as exc:
        lib_common.ErrorMessageHtml("CallbackQuery exception:%s in %s"% (str(exc), qry_select))

    cgiEnv.OutCgiRdf("LAYOUT_RECT", [prop_sql_query])


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


