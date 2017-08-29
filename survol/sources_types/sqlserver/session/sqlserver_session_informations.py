#!/usr/bin/python

"""
Information about an SQL Server session (ODBC)
"""

import sys
import lib_util
import lib_common
from lib_properties import pc
from sources_types.odbc import dsn as survol_odbc_dsn
from sources_types.sqlserver import dsn as survol_sqlserver_dsn
from sources_types import sqlserver
from sources_types.sqlserver import session
from sources_types.sqlserver import query as sqlserver_query

def GetInfoConnections(grph,sessionId,nodeSession,cnxn):
	sys.stderr.write("GetInfoConnections\n")
	cursorConnections = cnxn.cursor()

	qryConnections = """
	select net_transport, protocol_type,auth_scheme, connect_time,last_read,last_write,
	local_net_address,local_tcp_port,client_net_address,client_tcp_port
	from sys.dm_exec_connections where session_id=%s
	""" % sessionId

	for rowConnections in cursorConnections.execute(qryConnections):
		grph.add( (nodeSession, lib_common.MakeProp("Net transport"), lib_common.NodeLiteral(rowConnections.net_transport) ) )
		grph.add( (nodeSession, lib_common.MakeProp("Protocol type"), lib_common.NodeLiteral(rowConnections.protocol_type) ) )
		grph.add( (nodeSession, lib_common.MakeProp("Auth scheme"), lib_common.NodeLiteral(rowConnections.auth_scheme) ) )
		grph.add( (nodeSession, lib_common.MakeProp("Connect time"), lib_common.NodeLiteral(rowConnections.connect_time) ) )
		grph.add( (nodeSession, lib_common.MakeProp("Last read"), lib_common.NodeLiteral(rowConnections.last_read) ) )
		grph.add( (nodeSession, lib_common.MakeProp("Last write"), lib_common.NodeLiteral(rowConnections.last_write) ) )



#session_id	login_time	host_name	program_name	host_process_id	client_version	client_interface_name	security_id	login_name	nt_domain	nt_user_name	status	context_info	cpu_time	memory_usage	total_scheduled_time	total_elapsed_time	endpoint_id	last_request_start_time	last_request_end_time	reads	writes	logical_reads	is_user_process	text_size	language	date_format	date_first	quoted_identifier	arithabort	ansi_null_dflt_on	ansi_defaults	ansi_warnings	ansi_padding	ansi_nulls	concat_null_yields_null	transaction_isolation_level	lock_timeout	deadlock_priority	row_count	prev_error	original_security_id	original_login_name	last_successful_logon	last_unsuccessful_logon	unsuccessful_logons	group_id	database_id	authenticating_database_id	open_transaction_count
#51	2016-10-05 22:39:24.103	RCHATEAU-HP	Microsoft SQL Server Management Studio	7308	7	.Net SqlClient Data Provider	0x0105000000000005150000006CA699C7AD13C31ABF7CF539E9030000	rchateau-HP\rchateau	rchateau-HP	rchateau	sleeping	0x	109	2	6359	10196	2	2016-10-05 22:39:47.830	2016-10-05 22:39:47.850	145	5	816	1	-1	us_english	mdy	7	1	0	1	0	1	1	1	1	2	10000	0	1	0	0x0105000000000005150000006CA699C7AD13C31ABF7CF539E9030000	rchateau-HP\rchateau	NULL	NULL	NULL	1	1	1	0

def GetInfoSessions(grph,sessionId,nodeSession,cnxn):
	sys.stderr.write("GetInfoSessions\n")
	cursorSessions = cnxn.cursor()

	qrySessions = """
	SELECT host_name,program_name,client_interface_name,login_name,last_request_start_time,last_request_end_time,login_time
	FROM sys.dm_exec_sessions where session_id=%s
	""" % sessionId

	for rowSessions in cursorSessions.execute(qrySessions):
		grph.add( (nodeSession, lib_common.MakeProp("Client interface"), lib_common.NodeLiteral(rowSessions.client_interface_name) ) )
		grph.add( (nodeSession, lib_common.MakeProp("Login"), lib_common.NodeLiteral(rowSessions.login_name) ) )
		if rowSessions.program_name:
			grph.add( (nodeSession, lib_common.MakeProp("Program"), lib_common.NodeLiteral(rowSessions.program_name) ) )

		grph.add( (nodeSession, lib_common.MakeProp("Login time"), lib_common.NodeLiteral(rowSessions.login_time) ) )
		grph.add( (nodeSession, lib_common.MakeProp("Last request start"), lib_common.NodeLiteral(rowSessions.last_request_start_time) ) )
		if rowSessions.last_request_end_time:
			grph.add( (nodeSession, lib_common.MakeProp("Last request end"), lib_common.NodeLiteral(rowSessions.last_request_end_time) ) )

# session_id	request_id	start_time	status	command	sql_handle	statement_start_offset	statement_end_offset	plan_handle	database_id	user_id	connection_id	blocking_session_id	wait_type	wait_time	last_wait_type	wait_resource	open_transaction_count	open_resultset_count	transaction_id	context_info	percent_complete	estimated_completion_time	cpu_time	total_elapsed_time	scheduler_id	task_address	reads	writes	logical_reads	text_size	language	date_format	date_first	quoted_identifier	arithabort	ansi_null_dflt_on	ansi_defaults	ansi_warnings	ansi_padding	ansi_nulls	concat_null_yields_null	transaction_isolation_level	lock_timeout	deadlock_priority	row_count	prev_error	nest_level	granted_query_memory	executing_managed_code	group_id	query_hash	query_plan_hash
# 52	0	2016-10-12 07:45:14.517	running	SELECT	0x020000002D0B29014FC51CF6BC91B0030176167B618C933900000000000000000000000000000000	172	2068	0x060001002D0B2901601CFD1101000000000000000000000000000000000000000000000000000000	1	1	853F7FC5-B1BD-4E06-8B3C-02E05EA0559E	0	NULL	0	MISCELLANEOUS		0	1	477413	0x	0	0	0	2	0	0x0ACBC6D8	0	0	0	2147483647	us_english	mdy	7	1	1	1	0	1	1	1	1	2	-1	0	1	0	0	0	0	1	0xF83AFF24E2C5E377	0x5C3C1D2A449D0B70
def GetInfoRequests(grph,sessionId,nodeSession,cnxn,dsnNam):
	sys.stderr.write("GetInfoRequests\n")
	cursorRequests = cnxn.cursor()
	# select sqltext.TEXT, status, command from sys.dm_exec_requests
	# CROSS APPLY sys.dm_exec_sql_text(sql_handle) AS sqltext

	qryRequests = """
	select sqltext.TEXT, status, command from sys.dm_exec_requests
	CROSS APPLY sys.dm_exec_sql_text(sql_handle) AS sqltext
	where session_id=%s
	""" % sessionId

	propSqlServerSqlQuery = lib_common.MakeProp("Sql query")

	# TODO: Very often, it does not display anything.
	for rowRequests in cursorRequests.execute(qryRequests):
		grph.add( (nodeSession, lib_common.MakeProp("Status"), lib_common.NodeLiteral(rowRequests.status) ) )
		grph.add( (nodeSession, lib_common.MakeProp("Command"), lib_common.NodeLiteral(rowRequests.command) ) )

		# nodeSqlQuery = sql_query.MakeUri(rowRequests.TEXT,"sqlserver/query",{"Dsn":"Tralala"})
		nodeSqlQuery = sqlserver_query.MakeUri(rowRequests.TEXT,dsnNam)
		grph.add((nodeSession, propSqlServerSqlQuery, nodeSqlQuery))



try:
	import pyodbc
except ImportError:
	lib_common.ErrorMessageHtml("pyodbc Python library not installed")

def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	dsnNam = survol_odbc_dsn.GetDsnNameFromCgi(cgiEnv)
	sessionId = cgiEnv.m_entity_id_dict["SessionId"]

	sys.stderr.write("dsn=(%s) sessionId=%s\n" % (dsnNam,sessionId))

	nodeSession = survol_sqlserver_dsn.MakeUri(dsnNam)

	ODBC_ConnectString = survol_odbc_dsn.MakeOdbcConnectionString(dsnNam)
	try:
		cnxn = pyodbc.connect(ODBC_ConnectString)
		sys.stderr.write("Connected: %s\n" % dsnNam)

		grph.add( (nodeSession, lib_common.MakeProp("Session id"), lib_common.NodeLiteral(sessionId) ) )
		GetInfoConnections(grph,sessionId,nodeSession,cnxn)
		GetInfoSessions(grph,sessionId,nodeSession,cnxn)
		GetInfoRequests(grph,sessionId,nodeSession,cnxn,dsnNam)

	except Exception:
		exc = sys.exc_info()[0]
		lib_common.ErrorMessageHtml(
			"nodeDsn=%s Unexpected error:%s" % (dsnNam, str(sys.exc_info())))

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()



# http://www.easysoft.com/developer/languages/python/pyodbc.html
