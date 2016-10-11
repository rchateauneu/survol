#!/usr/bin/python

"""
Queries running in SQL Server database (ODBC)
"""

import sys
import rdflib
import lib_util
import lib_common
from lib_properties import pc
from sources_types.odbc import dsn as survol_odbc_dsn
from sources_types.sqlserver import dsn as survol_sqlserver_dsn
from sources_types import sqlserver
from sources_types.sqlserver import session

from sources_types import sql
from sources_types.sql import query


try:
	import pyodbc
except ImportError:
	lib_common.ErrorMessageHtml("pyodbc Python library not installed")

def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = rdflib.Graph()

	dsnNam = cgiEnv.m_entity_id_dict["Dsn"]

	sys.stderr.write("dsn=(%s)\n" % dsnNam)

	nodeDsn = survol_sqlserver_dsn.MakeUri(dsnNam)

	ODBC_ConnectString = survol_odbc_dsn.MakeOdbcConnectionString(dsnNam)
	try:
		cnxn = pyodbc.connect(ODBC_ConnectString)
		sys.stderr.write("Connected: %s\n" % dsnNam)
		cursorQueries = cnxn.cursor()

		qryQueries = """
			SELECT sqltext.TEXT,
			req.session_id,
			req.status,
			sess.host_process_id,
			sess.host_name
			FROM sys.dm_exec_requests req
			CROSS APPLY sys.dm_exec_sql_text(sql_handle) AS sqltext
			, sys.dm_exec_sessions sess
			where sess.session_id = req.session_id
		"""

		propSqlQuery = lib_common.MakeProp("Sql query")
		propHostProcess = lib_common.MakeProp("Host process")
		propStatus = lib_common.MakeProp("Status")

		for rowQry in cursorQueries.execute(qryQueries):
			sys.stderr.write("rowQry.session_id=(%s)\n" % rowQry.session_id)
			nodeSession = session.MakeUri(dsnNam, rowQry.session_id)

			nodeSqlQuery = query.MakeUri(rowQry.TEXT)
			grph.add((nodeSession, propSqlQuery, nodeSqlQuery))
			node_process = lib_common.RemoteBox(rowQry.host_name).PidUri(rowQry.host_process_id)
			grph.add((nodeSession, propHostProcess, node_process))
			grph.add((nodeSession, propStatus, rdflib.Literal(rowQry.status)))

	except Exception:
		exc = sys.exc_info()[0]
		lib_common.ErrorMessageHtml(
			"nodeDsn=%s Unexpected error:%s" % (dsnNam, str(sys.exc_info())))

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()



# http://www.easysoft.com/developer/languages/python/pyodbc.html
