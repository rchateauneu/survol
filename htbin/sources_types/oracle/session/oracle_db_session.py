#!/usr/bin/python

"""
Oracle session details
"""

import sys
import lib_oracle
import rdflib
import lib_common
from lib_properties import pc

from sources_types.oracle import schema as oracle_schema
from sources_types.oracle import session as oracle_session


# Associer a chaque table oracle une classe dynamique (Ce que ne peut pas faire wbem et wmi)
# C est une autre definition. Eventuellement en parallele.
# ( Idem : Les schemas Oracle deviennent des namespaces (Je vois moins l interet). )
# L interet est que du WQL est identique fonctionnellement a du SQL.
#
# Il faudrait comprendre  les liens entre tables, avec les requetes et les index.
# Autre application du parsing des requetes :
# - On voit que tel process depend de telle table,
# - on visualise la table avec ses champs
# - On fait pointer les champs vers les champs d autres tables,
# si une query fait une jointure sur ces deux champs.
# C est dans la meme logique d explorer grossierement des relations entre des composants logiciels.
# On pourrait aussi grepper avec "strings" les requetes statiques dans un .exe ou une dll.
#
# Donc l execution d un process va envoyer toutes sortes d infos en vrac,
# pas forcement des choses qui le concerne directement (Comme les requetes SQL et les liens entre tables)
#
# J y pense : Qu est ce que on peut faire avec l analyse statique du code ?
#
#	"oracle_session"      : ( ["Db","Session"], ),
def Main():
	cgiEnv = lib_oracle.OracleEnv()
	oraSession = cgiEnv.m_entity_id_dict["Session"]
	grph = cgiEnv.GetGraph()
	node_oraSession = oracle_session.MakeUri( cgiEnv.m_oraDatabase, oraSession )

	# TYPE = "VIEW", "TABLE", "PACKAGE BODY"
	sql_query = "select SID,STATUS,USERNAME,SERVER,SCHEMANAME,COMMAND,MACHINE,PORT,OSUSER,PROCESS,SERVICE_NAME,ACTION from V$SESSION where SID='%s'" % oraSession
	sys.stderr.write("sql_query=%s\n" % sql_query )
	result = lib_oracle.ExecuteQuery( cgiEnv.ConnectStr(), sql_query)

	# There should be only one.
	for row in result:
		sys.stderr.write("SID=%s\n" % row[0] )

		grph.add( ( node_oraSession, lib_common.MakeProp("Status"), rdflib.Literal(row[1]) ) )
		grph.add( ( node_oraSession, lib_common.MakeProp("Username"), rdflib.Literal(row[2]) ) )
		grph.add( ( node_oraSession, lib_common.MakeProp("Server"), rdflib.Literal(row[3]) ) )

		# grph.add( ( node_oraSession, lib_common.MakeProp("Schema"), rdflib.Literal(row[4]) ) )
		nodeSchema = oracle_schema.MakeUri(cgiEnv.m_oraDatabase, str(row[4]) )
		grph.add( ( node_oraSession, pc.property_oracle_schema, nodeSchema ) )

		grph.add( ( node_oraSession, lib_common.MakeProp("Command"), rdflib.Literal(row[5]) ) )

		# This returns an IP address from "WORKGROUP\RCHATEAU-HP"
		user_machine = lib_oracle.OraMachineToIp(row[6])
		nodeMachine = lib_common.gUriGen.HostnameUri(user_machine)
		grph.add( ( nodeMachine, pc.property_information, rdflib.Literal(row[6]) ) )

		grph.add( ( node_oraSession, lib_common.MakeProp("Port"), rdflib.Literal(row[7]) ) )
		grph.add( ( node_oraSession, lib_common.MakeProp("OsUser"), rdflib.Literal(row[8]) ) )
		# grph.add( ( node_oraSession, lib_common.MakeProp("Process"), rdflib.Literal(row[9]) ) )
		sessPidTid = row[9] # 7120:4784
		sessPid = sessPidTid.split(":")[0]
		node_process = lib_common.RemoteBox(user_machine).PidUri( sessPid )
		grph.add( ( node_process, lib_common.MakeProp("Pid"), rdflib.Literal(sessPid) ) )
		grph.add( ( node_oraSession, pc.property_oracle_session, node_process ) )

		grph.add( ( node_oraSession, lib_common.MakeProp("Hostname"), nodeMachine ) )

		grph.add( ( node_oraSession, lib_common.MakeProp("ServiceName"), rdflib.Literal(row[10]) ) )
		grph.add( ( node_oraSession, lib_common.MakeProp("Action"), rdflib.Literal(row[11]) ) )


	cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT")

if __name__ == '__main__':
	Main()


# Not done yet.

# Just gives the details of an Oracle session.

# SQL> desc v$session
# Name                                      Null?    Type
# ----------------------------------------- -------- ----------------------------
# SADDR                                              RAW(8)
# SID                                                NUMBER
# SERIAL#                                            NUMBER
# AUDSID                                             NUMBER
# PADDR                                              RAW(8)
# USER#                                              NUMBER
# USERNAME                                           VARCHAR2(30)
# COMMAND                                            NUMBER
# OWNERID                                            NUMBER
# TADDR                                              VARCHAR2(16)
# LOCKWAIT                                           VARCHAR2(16)
# STATUS                                             VARCHAR2(8)
# SERVER                                             VARCHAR2(9)
# SCHEMA#                                            NUMBER
# SCHEMANAME                                         VARCHAR2(30)
# OSUSER                                             VARCHAR2(30)
# PROCESS                                            VARCHAR2(24)
# MACHINE                                            VARCHAR2(64)
# PORT                                               NUMBER
# TERMINAL                                           VARCHAR2(16)
# PROGRAM                                            VARCHAR2(64)
# TYPE                                               VARCHAR2(10)
# SQL_ADDRESS                                        RAW(8)
# SQL_HASH_VALUE                                     NUMBER
# SQL_ID                                             VARCHAR2(13)
# SQL_CHILD_NUMBER                                   NUMBER
# SQL_EXEC_START                                     DATE
# SQL_EXEC_ID                                        NUMBER
# PREV_SQL_ADDR                                      RAW(8)
# PREV_HASH_VALUE                                    NUMBER
# PREV_SQL_ID                                        VARCHAR2(13)
# PREV_CHILD_NUMBER                                  NUMBER
# PREV_EXEC_START                                    DATE
# PREV_EXEC_ID                                       NUMBER
# PLSQL_ENTRY_OBJECT_ID                              NUMBER
# PLSQL_ENTRY_SUBPROGRAM_ID                          NUMBER
# PLSQL_OBJECT_ID                                    NUMBER
# PLSQL_SUBPROGRAM_ID                                NUMBER
# MODULE                                             VARCHAR2(64)
# MODULE_HASH                                        NUMBER
# ACTION                                             VARCHAR2(64)
# ACTION_HASH                                        NUMBER
# CLIENT_INFO                                        VARCHAR2(64)
# FIXED_TABLE_SEQUENCE                               NUMBER
# ROW_WAIT_OBJ#                                      NUMBER
# ROW_WAIT_FILE#                                     NUMBER
# ROW_WAIT_BLOCK#                                    NUMBER
# ROW_WAIT_ROW#                                      NUMBER
# TOP_LEVEL_CALL#                                    NUMBER
# LOGON_TIME                                         DATE
# LAST_CALL_ET                                       NUMBER
# PDML_ENABLED                                       VARCHAR2(3)
# FAILOVER_TYPE                                      VARCHAR2(13)
# FAILOVER_METHOD                                    VARCHAR2(10)
# FAILED_OVER                                        VARCHAR2(3)
# RESOURCE_CONSUMER_GROUP                            VARCHAR2(32)
# PDML_STATUS                                        VARCHAR2(8)
# PDDL_STATUS                                        VARCHAR2(8)
# PQ_STATUS                                          VARCHAR2(8)
# CURRENT_QUEUE_DURATION                             NUMBER
# CLIENT_IDENTIFIER                                  VARCHAR2(64)
# BLOCKING_SESSION_STATUS                            VARCHAR2(11)
# BLOCKING_INSTANCE                                  NUMBER
# BLOCKING_SESSION                                   NUMBER
# FINAL_BLOCKING_SESSION_STATUS                      VARCHAR2(11)
# FINAL_BLOCKING_INSTANCE                            NUMBER
# FINAL_BLOCKING_SESSION                             NUMBER
# SEQ#                                               NUMBER
# EVENT#                                             NUMBER
# EVENT                                              VARCHAR2(64)
# P1TEXT                                             VARCHAR2(64)
# P1                                                 NUMBER
# P1RAW                                              RAW(8)
# P2TEXT                                             VARCHAR2(64)
# P2                                                 NUMBER
# P2RAW                                              RAW(8)
# P3TEXT                                             VARCHAR2(64)
# P3                                                 NUMBER
# P3RAW                                              RAW(8)
# WAIT_CLASS_ID                                      NUMBER
# WAIT_CLASS#                                        NUMBER
# WAIT_CLASS                                         VARCHAR2(64)
# WAIT_TIME                                          NUMBER
# SECONDS_IN_WAIT                                    NUMBER
# STATE                                              VARCHAR2(19)
# WAIT_TIME_MICRO                                    NUMBER
# TIME_REMAINING_MICRO                               NUMBER
# TIME_SINCE_LAST_WAIT_MICRO                         NUMBER
# SERVICE_NAME                                       VARCHAR2(64)
# SQL_TRACE                                          VARCHAR2(8)
# SQL_TRACE_WAITS                                    VARCHAR2(5)
# SQL_TRACE_BINDS                                    VARCHAR2(5)
# SQL_TRACE_PLAN_STATS                               VARCHAR2(10)
# SESSION_EDITION_ID                                 NUMBER
# CREATOR_ADDR                                       RAW(8)
# CREATOR_SERIAL#                                    NUMBER
# ECID                                               VARCHAR2(64)
#
