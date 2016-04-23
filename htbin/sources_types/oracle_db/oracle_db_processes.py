import sys
import lib_common
import socket
from lib_properties import pc
import lib_oracle
import rdflib

def Main():
	cgiEnv = lib_oracle.OracleEnv( "Oracle database's connected processes" )

	grph = rdflib.Graph()

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


	sql_query = """
	SELECT distinct sess.sid, sess.username, sess.schemaname, proc.spid,pid,sess.osuser,sess.machine,sess.process,
	sess.port,proc.terminal,sess.program,proc.tracefile
	  FROM v$session sess,
		   v$process proc
	 WHERE sess.type     = 'USER'
	   and sess.paddr = proc.addr
	"""

	node_oradb = lib_common.gUriGen.OracleDbUri( cgiEnv.m_oraDatabase )

	result = lib_oracle.ExecuteQuery( cgiEnv.ConnectStr(), sql_query)

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

		# Process and Thread id of the CLIENT program, executing sqlplus.exe for example.
		sessPidTid = row[7] # 7120:4784
		sessPid = sessPidTid.split(":")[0]
		procTerminal = row[9]
		sessProgram = row[10]

		nodeSession = lib_common.gUriGen.OracleSessionUri( cgiEnv.m_oraDatabase, str(row[0]) )
		grph.add( ( nodeSession, lib_common.MakeProp("Oracle user"), rdflib.Literal(oraUsername) ) )
		grph.add( ( nodeSession, lib_common.MakeProp("Schema"), rdflib.Literal(schemaName) ) )
		grph.add( ( nodeSession, lib_common.MakeProp("Program"), rdflib.Literal(sessProgram) ) )

		if schemaName != None:
			nodeSchema = lib_common.gUriGen.OracleSchemaUri(cgiEnv.m_oraDatabase, str(schemaName) )
			grph.add( ( nodeSession, pc.property_oracle_schema, nodeSchema ) )
			grph.add( ( node_oradb, pc.property_oracle_db, nodeSchema ) )

		sys.stderr.write("user_proc_id=%s user_machine=%s\n" % (user_proc_id,user_machine))
		node_process = lib_common.RemoteBox(user_machine).PidUri( sessPid )
		grph.add( ( node_process, lib_common.MakeProp("SystemPid"), rdflib.Literal(user_proc_id) ) )
		grph.add( ( node_process, lib_common.MakeProp("OraclePid"), rdflib.Literal(process_pid) ) )
		grph.add( ( node_process, lib_common.MakeProp("Terminal"), rdflib.Literal(procTerminal) ) )
		grph.add( ( nodeSession, pc.property_oracle_session, node_process ) )

		if sessOsuser != None:
			nodeOsUser = lib_common.RemoteBox(user_machine).UserUri(sessOsuser)
			grph.add( ( nodeOsUser, lib_common.MakeProp("OsUser"), rdflib.Literal(sessOsuser) ) )
			grph.add( ( node_process, pc.property_user, nodeOsUser ) )

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()
