#!/usr/bin/python

# Display processes running in this database.

"""
Processes running in ODBC DSN (SQL Server only)
"""

import sys
import rdflib
import lib_util
import lib_common
from lib_properties import pc
from sources_types import odbc as survol_odbc
from sources_types.odbc import dsn as survol_dsn

try:
	import pyodbc
except ImportError:
	lib_common.ErrorMessageHtml("pyodbc Python library not installed")

# PROBABLY, THIS SHOULD GO INTO A NEW TYPE sqlserver
from sources_types import sqlserver
from sources_types.sqlserver import session

# Depends on the type of odbc_driver: "SQL Server Native Client 11.0", "SQL Server", "Oracle in XE" etc...
# xid=odbc/dsn.Dsn=MyOracleDataSource , odbc_driver=Oracle in XE
# xid=odbc/dsn.Dsn=SqlSrvNativeDataSource , odbc_driver=SQL Server Native Client 11.0
# xid=odbc/dsn.Dsn=SysDataSourceSQLServer , odbc_driver=SQL Server
def Usable(entity_type,entity_ids_arr):
	"""SQL Server database only"""
	dsnNam = entity_ids_arr[0]
	dbEntityType = survol_dsn.GetDatabaseEntityType(dsnNam)

	return dbEntityType == "sqlserver"



# Difficulte: C est completement specifique a Sql Server mais on y arrive par ODBC.
# Pour le moment, on na pas d acces a SqlServer par Python.

def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = rdflib.Graph()

	dsnNam = cgiEnv.m_entity_id_dict["Dsn"]

	sys.stderr.write("dsn=(%s)\n" % dsnNam)

	nodeDsn = lib_common.gUriGen.OdbcDsnUri(dsnNam)

	ODBC_ConnectString = survol_odbc.MakeOdbcConnectionString(dsnNam)
	try:
		cnxn = pyodbc.connect(ODBC_ConnectString)
		sys.stderr.write("Connected: %s\n" % dsnNam)
		cursorSessions = cnxn.cursor()

		qrySessions = """
		SELECT host_name,host_process_id,session_id,program_name,client_interface_name,original_login_name,nt_domain,nt_user_name
		FROM sys.dm_exec_sessions where host_name is not null
		"""

		# for rowSess in cursorSessions.execute(qrySessions)

		#cursorSessions.execute(qrySessions)
		#fetchSessions = cursorSessions.fetchall()
		#for rowSess in cursorSessions.columns(table='sys.dm_exec_sessions'):

		for rowSess in cursorSessions.execute(qrySessions):
			sys.stderr.write("rowSess.session_id=(%s)\n" % rowSess.session_id)
			nodeSession = session.MakeUri(dsnNam, rowSess.session_id)
			sys.stderr.write("2rowSess.session_id=(%s)\n" % rowSess.session_id)
			grph.add((nodeDsn, lib_common.MakeProp("SqlServer session"), nodeSession))

			node_process = lib_common.RemoteBox(rowSess.host_name).PidUri(rowSess.host_process_id)
			grph.add((nodeSession, lib_common.MakeProp("Host process"), node_process))
			grph.add((nodeSession, lib_common.MakeProp("Program name"), rdflib.Literal(rowSess.program_name)))
			grph.add(
				(nodeSession, lib_common.MakeProp("Client Interface"), rdflib.Literal(rowSess.client_interface_name)))

			# TODO: Make nodes with these:

			grph.add(
				(nodeSession, lib_common.MakeProp("original_login_name"), rdflib.Literal(rowSess.original_login_name)))
			grph.add((nodeSession, lib_common.MakeProp("nt_domain"), rdflib.Literal(rowSess.nt_domain)))
			grph.add((nodeSession, lib_common.MakeProp("nt_user_name"), rdflib.Literal(rowSess.nt_user_name)))

		# nodeOsUser = lib_common.RemoteBox(user_machine).UserUri(sessOsuser)
		# grph.add( ( nodeOsUser, lib_common.MakeProp("OsUser"), rdflib.Literal(sessOsuser) ) )

	except Exception:
		exc = sys.exc_info()[0]
		lib_common.ErrorMessageHtml(
			"nodeDsn=%s Unexpected error:%s" % (dsnNam, str(sys.exc_info())))  # cgiEnv.OutCgiRdf(grph)

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()



# http://www.easysoft.com/developer/languages/python/pyodbc.html
