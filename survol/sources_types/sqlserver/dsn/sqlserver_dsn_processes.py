#!/usr/bin/python

# Display processes running in this database.

"""
Processes running in SQL Server database (ODBC)
"""

import sys
import lib_common
from lib_properties import pc
from sources_types.odbc import dsn as survol_odbc_dsn
from sources_types.sqlserver import dsn as survol_sqlserver_dsn
from sources_types.sqlserver import session

try:
	import pyodbc
except ImportError:
	lib_common.ErrorMessageHtml("pyodbc Python library not installed")

def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	dsnNam = survol_odbc_dsn.GetDsnNameFromCgi(cgiEnv)

	sys.stderr.write("dsn=(%s)\n" % dsnNam)

	nodeDsn = survol_sqlserver_dsn.MakeUri(dsnNam)

	ODBC_ConnectString = survol_odbc_dsn.MakeOdbcConnectionString(dsnNam)
	try:
		cnxn = pyodbc.connect(ODBC_ConnectString)
		sys.stderr.write("Connected: %s\n" % dsnNam)
		cursorSessions = cnxn.cursor()

		qrySessions = """
		SELECT host_name,host_process_id,session_id,program_name,client_interface_name,original_login_name,nt_domain,nt_user_name
		FROM sys.dm_exec_sessions where host_process_id is not null
		"""

		propSqlServerSession = lib_common.MakeProp("SqlServer session")
		propSqlServerHostProcess = lib_common.MakeProp("Host process")
		propSqlServerProgramName = lib_common.MakeProp("Program name")
		propSqlServerClientInterface = lib_common.MakeProp("Client Interface")

		propSqlServerOriginalLoginName = lib_common.MakeProp("original_login_name")
		propSqlServerNTDomain = lib_common.MakeProp("nt_domain")
		propSqlServerNTUserName = lib_common.MakeProp("nt_user_name")

		for rowSess in cursorSessions.execute(qrySessions):
			sys.stderr.write("rowSess.session_id=(%s)\n" % rowSess.session_id)
			nodeSession = session.MakeUri(dsnNam, rowSess.session_id)
			grph.add((nodeDsn, propSqlServerSession, nodeSession))

			node_process = lib_common.RemoteBox(rowSess.host_name).PidUri(rowSess.host_process_id)
			grph.add((node_process, pc.property_pid, lib_common.NodeLiteral(rowSess.host_process_id)))

			grph.add((nodeSession, propSqlServerHostProcess, node_process))
			grph.add((nodeSession, propSqlServerProgramName, lib_common.NodeLiteral(rowSess.program_name)))
			grph.add((nodeSession, propSqlServerClientInterface, lib_common.NodeLiteral(rowSess.client_interface_name)))

			# TODO: Make nodes with these:

			grph.add(
				(nodeSession, propSqlServerOriginalLoginName, lib_common.NodeLiteral(rowSess.original_login_name)))
			grph.add((nodeSession, propSqlServerNTDomain, lib_common.NodeLiteral(rowSess.nt_domain)))
			grph.add((nodeSession, propSqlServerNTUserName, lib_common.NodeLiteral(rowSess.nt_user_name)))

	except Exception:
		exc = sys.exc_info()[0]
		lib_common.ErrorMessageHtml(
			"nodeDsn=%s Unexpected error:%s" % (dsnNam, str(sys.exc_info())))  # cgiEnv.OutCgiRdf()

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()

# http://www.easysoft.com/developer/languages/python/pyodbc.html
