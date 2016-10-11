#!/usr/bin/python

"""
Information about an SQL Server database (ODBC)
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
	sessionId = cgiEnv.m_entity_id_dict["SessionId"]

	sys.stderr.write("dsn=(%s) sessionId=%s\n" % (dsnNam,sessionId))

	nodeDsn = survol_sqlserver_dsn.MakeUri(dsnNam)
	nodeSession = survol_sqlserver_dsn.MakeUri(dsnNam)

	ODBC_ConnectString = survol_odbc_dsn.MakeOdbcConnectionString(dsnNam)
	try:
		cnxn = pyodbc.connect(ODBC_ConnectString)
		sys.stderr.write("Connected: %s\n" % dsnNam)
		cursorConnections = cnxn.cursor()

		qryConnections = """
		select net_transport, protocol_type,auth_scheme, connect_time,last_read,last_write,
		local_net_address,local_tcp_port,client_net_address,client_tcp_port
		from sys.dm_exec_connections where session_id=%s
		""" % sessionId

		for rowConnections in cursorConnections.execute(qryConnections):
			grph.add( (nodeSession, lib_common.MakeProp("Net transport"), rdflib.Literal(rowConnections.net_transport) ) )
			grph.add( (nodeSession, lib_common.MakeProp("Protocol type"), rdflib.Literal(rowConnections.protocol_type) ) )
			grph.add( (nodeSession, lib_common.MakeProp("Auth scheme"), rdflib.Literal(rowConnections.auth_scheme) ) )
			grph.add( (nodeSession, lib_common.MakeProp("Connect time"), rdflib.Literal(rowConnections.connect_time) ) )
			grph.add( (nodeSession, lib_common.MakeProp("Last read"), rdflib.Literal(rowConnections.last_read) ) )
			grph.add( (nodeSession, lib_common.MakeProp("Last write"), rdflib.Literal(rowConnections.last_write) ) )


	except Exception:
		exc = sys.exc_info()[0]
		lib_common.ErrorMessageHtml(
			"nodeDsn=%s Unexpected error:%s" % (dsnNam, str(sys.exc_info())))

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()



# http://www.easysoft.com/developer/languages/python/pyodbc.html
