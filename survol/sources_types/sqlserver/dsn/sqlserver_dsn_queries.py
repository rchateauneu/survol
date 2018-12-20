#!/usr/bin/python

"""
Queries running in SQL Server database (ODBC)
"""

import sys
import lib_common
from lib_properties import pc
from sources_types.odbc import dsn as survol_odbc_dsn
from sources_types.sqlserver import dsn as survol_sqlserver_dsn
from sources_types.sqlserver import session
from sources_types.sqlserver import query as sql_query


try:
	import pyodbc
except ImportError:
	lib_common.ErrorMessageHtml("pyodbc Python library not installed")

def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	dsnNam = survol_odbc_dsn.GetDsnNameFromCgi(cgiEnv)

	DEBUG("dsn=(%s)", dsnNam)

	nodeDsn = survol_sqlserver_dsn.MakeUri(dsnNam)

	ODBC_ConnectString = survol_odbc_dsn.MakeOdbcConnectionString(dsnNam)
	try:
		cnxn = pyodbc.connect(ODBC_ConnectString)
		DEBUG("Connected: %s", dsnNam)
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

		propSqlServerSqlQuery = lib_common.MakeProp("Sql query")
		propSqlServerHostProcess = lib_common.MakeProp("Host process")
		propSqlServerStatus = lib_common.MakeProp("Status")

		for rowQry in cursorQueries.execute(qryQueries):
			DEBUG("rowQry.session_id=(%s)", rowQry.session_id)
			nodeSession = session.MakeUri(dsnNam, rowQry.session_id)

			# A bit of cleanup.
			queryClean = rowQry.TEXT.replace("\n", " ").strip()

			# TODO: Must add connection information so we can go from the tables to sqlserver itself.
			nodeSqlQuery = sql_query.MakeUri(queryClean,dsnNam)
			grph.add((nodeSession, propSqlServerSqlQuery, nodeSqlQuery))
			node_process = lib_common.RemoteBox(rowQry.host_name).PidUri(rowQry.host_process_id)
			grph.add((node_process, pc.property_pid, lib_common.NodeLiteral(rowQry.host_process_id)))

			grph.add((nodeSession, propSqlServerHostProcess, node_process))
			grph.add((nodeSession, propSqlServerStatus, lib_common.NodeLiteral(rowQry.status)))

	except Exception:
		exc = sys.exc_info()[0]
		lib_common.ErrorMessageHtml(
			"nodeDsn=%s Unexpected error:%s" % (dsnNam, str(sys.exc_info())))

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()



# http://www.easysoft.com/developer/languages/python/pyodbc.html
