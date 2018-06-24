#!/usr/bin/python

"""
Oracle database's connected processes
"""

import sys
import lib_common
import lib_util
from lib_properties import pc
import lib_oracle

from sources_types.oracle import db as oracle_db
from sources_types.oracle import session as oracle_session
from sources_types.oracle import schema as oracle_schema


def Main():
	cgiEnv = lib_oracle.OracleEnv()

	grph = cgiEnv.GetGraph()

	#v$process
	#PID	NUMBER	Oracle process identifier
	#SPID	VARCHAR2(12)	Operating system process identifier
	#USERNAME	VARCHAR2(15)	Operating system process username. Any two-task user coming across the network has "-T" appended to the username.
	#TERMINAL	VARCHAR2(30)	Operating system terminal identifier
	#PROGRAM	VARCHAR2(48)	Program in progress
	#
	#v$session
	#SID	NUMBER	Session identifier
	#USER#	NUMBER	Oracle user identifier
	#USERNAME	VARCHAR2(30)	Oracle username
	#COMMAND	NUMBER	Command in progress (last statement parsed); for a list of values, see Table 7-5. These values also appear in the AUDIT_ACTIONS table.
	#SCHEMA#	NUMBER	Schema user identifier
	#SCHEMANAME	VARCHAR2(30)	Schema user name
	#OSUSER	VARCHAR2(30)	Operating system client user name
	#PROCESS	VARCHAR2(12)	Operating system client process ID
	#MACHINE	VARCHAR2(64)	Operating system machine name
	#TERMINAL	VARCHAR2(30)	Operating system terminal name
	#PROGRAM	VARCHAR2(48)	Operating system program name

	# The Oracle user needs: grant select any dictionary to <user>;
	sql_query = """
	SELECT distinct sess.sid, sess.username, sess.schemaname, proc.spid,pid,sess.osuser,sess.machine,sess.process,
	sess.port,proc.terminal,sess.program,proc.tracefile
	  FROM v$session sess,
		   v$process proc
	 WHERE sess.type     = 'USER'
	   and sess.paddr = proc.addr
	"""

	node_oradb = oracle_db.MakeUri( cgiEnv.m_oraDatabase )

	try:
		result = lib_oracle.ExecuteQueryThrow( cgiEnv.ConnectStr(), sql_query)
	except:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("ExecuteQuery exception:%s in %s"% ( str(exc), sql_query ) )

	for row in result:
		if row[0] == None:
			continue
		# print("\nUser="+row[0])

		oraUsername = row[1] # SHOULD BE EQUAL TO schemaName
		schemaName = row[2]

		# C est un TID du process Oracle, et pas le process qui execute le program client. Z
		user_proc_id = row[3]
		process_pid = row[4]
		sessOsuser = row[5]

		# This returns an IP address from "WORKGROUP\RCHATEAU-HP"
		user_machine = lib_oracle.OraMachineToIp(row[6])
		theMachineBox = lib_common.MachineBox(user_machine)

		# Process and Thread id of the CLIENT program, executing sqlplus.exe for example.
		sessPidTid = row[7] # 7120:4784
		sessPid = sessPidTid.split(":")[0]
		procTerminal = row[9]
		sessProgram = row[10]

		nodeSession = oracle_session.MakeUri( cgiEnv.m_oraDatabase, str(row[0]) )
		grph.add( ( nodeSession, lib_common.MakeProp("Oracle user"), lib_common.NodeLiteral(oraUsername) ) )
		grph.add( ( nodeSession, lib_common.MakeProp("Schema"), lib_common.NodeLiteral(schemaName) ) )
		grph.add( ( nodeSession, lib_common.MakeProp("Program"), lib_common.NodeLiteral(sessProgram) ) )

		if schemaName != None:
			nodeSchema = oracle_schema.MakeUri(cgiEnv.m_oraDatabase, str(schemaName) )
			grph.add( ( nodeSession, pc.property_oracle_schema, nodeSchema ) )
			grph.add( ( node_oradb, pc.property_oracle_db, nodeSchema ) )

		sys.stderr.write("user_proc_id=%s user_machine=%s\n" % (user_proc_id,user_machine))
		# node_process = lib_common.RemoteBox(user_machine).PidUri( sessPid )
		node_process = theMachineBox.PidUri( sessPid )
		grph.add( ( node_process, lib_common.MakeProp("SystemPid"), lib_common.NodeLiteral(user_proc_id) ) )
		grph.add( ( node_process, lib_common.MakeProp("OraclePid"), lib_common.NodeLiteral(process_pid) ) )
		grph.add( ( node_process, lib_common.MakeProp("Terminal"), lib_common.NodeLiteral(procTerminal) ) )
		grph.add( ( nodeSession, pc.property_oracle_session, node_process ) )

		if sessOsuser != None:
			sys.stderr.write("user_machine=%s sessOsuser=%s\n"%(user_machine,sessOsuser))
			nodeOsUser = theMachineBox.UserUri(sessOsuser)
			grph.add( ( nodeOsUser, lib_common.MakeProp("OsUser"), lib_common.NodeLiteral(sessOsuser) ) )
			grph.add( ( node_process, pc.property_user, nodeOsUser ) )

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
