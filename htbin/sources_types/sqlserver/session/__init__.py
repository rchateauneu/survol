"""
Sqlserver session
"""

import sys
import six
import rdflib
import lib_common
from lib_properties import pc

from sources_types.odbc import dsn as survol_odbc_dsn
from sources_types.sqlserver import dsn as survol_sqlserver_dsn

try:
	import pyodbc
	pyodbcOk = True
except ImportError:
	pyodbcOk = False



# This is called by OntologyClassKeys(entity_type) when it needs the parameters f an tneity type.
def EntityOntology():
	return ( ["Dsn","SessionId"], )

def MakeUri(dsn,sessionId):
	return lib_common.gUriGen.UriMake("sqlserver/session",dsn,sessionId)


def AddInfo(grph,node,entity_ids_arr):
	dsnNam = six.u(entity_ids_arr[0])
	sessionId = six.u(entity_ids_arr[1])

	nodeDsn = survol_sqlserver_dsn.MakeUri(dsnNam)

	grph.add( (nodeDsn, lib_common.MakeProp("DSN"), node ) )

	#session_id	most_recent_session_id	connect_time	net_transport	protocol_type	protocol_version	endpoint_id	encrypt_option	auth_scheme	node_affinity	num_reads	num_writes	last_read	last_write	net_packet_size	client_net_address	client_tcp_port	local_net_address	local_tcp_port	connection_id	parent_connection_id	most_recent_sql_handle
	#51	51	2016-10-05 22:39:24.080	Shared memory	TSQL	1946157060	2	FALSE	NTLM	0	13	13	2016-10-05 22:39:47.830	2016-10-05 22:39:47.847	4096	<local machine>	NULL	NULL	NULL	51D43D11-6A16-4E19-A253-0974EEDC634D	NULL	0x0200000016EF4D1B4BF65E91FF63A5D60122505E5DC8928000000000000000000000000000000000
	#52	52	2016-10-05 22:40:20.290	Shared memory	TSQL	1946157060	2	FALSE	NTLM	0	26	54	2016-10-11 23:28:00.727	2016-10-11 23:28:00.907	4096	<local machine>	NULL	NULL	NULL	853F7FC5-B1BD-4E06-8B3C-02E05EA0559E	NULL	0x0200000057662721C982D2FDEBFA2D0F498272D162E569C100000000000000000000000000000000
	#53	53	2016-10-07 08:14:12.107	TCP	TSQL	1946157060	4	FALSE	NTLM	0	14	17	2016-10-07 08:23:14.487	2016-10-07 08:23:14.490	4096	192.168.1.83	54982	192.168.1.83	1433	E79ECEF0-FBAF-4B79-8FB9-7591406EC1CF	NULL	0x02000000768991061E4A50B1FE93FC2F7ED994402142AE8C00000000000000000000000000000000
	#57	57	2016-10-08 17:33:40.710	TCP	TSQL	1895825409	4	FALSE	NTLM	0	5	5	2016-10-08 17:33:40.763	2016-10-08 17:33:40.767	4096	192.168.1.83	64542	192.168.1.83	1433	D49BC4D8-3EB1-4353-A5B2-DF738D9677AB	NULL	0x00000000000000000000000000000000000000000000000000000000000000000000000000000000	# 52	52	2016-10-05 22:40:20.290	Shared memory	TSQL	1946157060	2	FALSE	NTLM	0	23	43	2016-10-10 22:13:22.113	2016-10-10 22:13:38.230	4096	<local machine>	NULL	NULL	NULL	853F7FC5-B1BD-4E06-8B3C-02E05EA0559E	NULL	0x02000000A44FA72C19569D8EB73D9D9470A15C14F7CC6B4B00000000000000000000000000000000

	if pyodbcOk:
		ODBC_ConnectString = survol_odbc_dsn.MakeOdbcConnectionString(dsnNam)
		cnxn = pyodbc.connect(ODBC_ConnectString)
		sys.stderr.write("Connected: %s\n" % dsnNam)
		cursorConnections = cnxn.cursor()

		qryConnections = """
		select net_transport, protocol_type,auth_scheme, connect_time,last_read,last_write,
		local_net_address,local_tcp_port,client_net_address,client_tcp_port
		from sys.dm_exec_connections where session_id=%s
		""" % sessionId

		for rowConnections in cursorConnections.execute(qryConnections):
			grph.add( (node, lib_common.MakeProp("Net transport"), rdflib.Literal(rowConnections.net_transport) ) )
			grph.add( (node, lib_common.MakeProp("Protocol type"), rdflib.Literal(rowConnections.protocol_type) ) )
			grph.add( (node, lib_common.MakeProp("Auth scheme"), rdflib.Literal(rowConnections.auth_scheme) ) )
			grph.add( (node, lib_common.MakeProp("Connect time"), rdflib.Literal(rowConnections.connect_time) ) )
			grph.add( (node, lib_common.MakeProp("Last read"), rdflib.Literal(rowConnections.last_read) ) )
			grph.add( (node, lib_common.MakeProp("Last write"), rdflib.Literal(rowConnections.last_write) ) )

			if rowConnections.net_transport == "TCP":
				lsocketNode = lib_common.gUriGen.AddrUri( rowConnections.local_net_address, rowConnections.local_tcp_port )
				rsocketNode = lib_common.gUriGen.AddrUri( rowConnections.client_net_address, rowConnections.client_tcp_port )
				grph.add( ( lsocketNode, pc.property_socket_end, rsocketNode ) )
				grph.add( ( node, pc.property_has_socket, lsocketNode ) )

