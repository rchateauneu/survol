#!/usr/bin/env python

"""
Oracle database's connected processes
"""

import sys
import logging
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
    #PID    NUMBER    Oracle process identifier
    #SPID    VARCHAR2(12)    Operating system process identifier
    #USERNAME    VARCHAR2(15)    Operating system process username. Any two-task user coming across the network has "-T" appended to the username.
    #TERMINAL    VARCHAR2(30)    Operating system terminal identifier
    #PROGRAM    VARCHAR2(48)    Program in progress
    #
    #v$session
    #SID    NUMBER    Session identifier
    #USER#    NUMBER    Oracle user identifier
    #USERNAME    VARCHAR2(30)    Oracle username
    #COMMAND    NUMBER    Command in progress (last statement parsed); for a list of values, see Table 7-5. These values also appear in the AUDIT_ACTIONS table.
    #SCHEMA#    NUMBER    Schema user identifier
    #SCHEMANAME    VARCHAR2(30)    Schema user name
    #OSUSER    VARCHAR2(30)    Operating system client user name
    #PROCESS    VARCHAR2(12)    Operating system client process ID
    #MACHINE    VARCHAR2(64)    Operating system machine name
    #TERMINAL    VARCHAR2(30)    Operating system terminal name
    #PROGRAM    VARCHAR2(48)    Operating system program name

    # The Oracle user needs: grant select any dictionary to <user>;
    sql_query = """
    SELECT distinct sess.sid, sess.username, sess.schemaname, proc.spid,pid,sess.osuser,sess.machine,sess.process,
    sess.port,proc.terminal,sess.program,proc.tracefile
      FROM v$session sess,
           v$process proc
     WHERE sess.type     = 'USER'
       and sess.paddr = proc.addr
    """

    node_oradb = oracle_db.MakeUri(cgiEnv.m_oraDatabase)

    try:
        result = lib_oracle.ExecuteQueryThrow(cgiEnv.ConnectStr(), sql_query)
    except Exception as exc:
        lib_common.ErrorMessageHtml("ExecuteQuery exception:%s in %s" % (str(exc), sql_query))

    for row in result:
        if row[0] == None:
            continue
        # print("\nUser="+row[0])

        ora_username = row[1] # SHOULD BE EQUAL TO schema_name
        schema_name = row[2]

        # It is a TID of the Oracleprocess, not the process running client code.
        user_proc_id = row[3]
        process_pid = row[4]
        sess_osuser = row[5]

        # This returns an IP address from "WORKGROUP\RCHATEAU-HP"
        user_machine = lib_oracle.OraMachineToIp(row[6])
        the_machine_box = lib_common.MachineBox(user_machine)

        # Process and Thread id of the CLIENT program, executing sqlplus.exe for example.
        sess_pid_tid = row[7] # 7120:4784
        sess_pid = sess_pid_tid.split(":")[0]
        proc_terminal = row[9]
        sess_program = row[10]

        node_session = oracle_session.MakeUri(cgiEnv.m_oraDatabase, str(row[0]))
        grph.add((node_session, lib_common.MakeProp("Oracle user"), lib_util.NodeLiteral(ora_username)))
        grph.add((node_session, lib_common.MakeProp("Schema"), lib_util.NodeLiteral(schema_name)))
        grph.add((node_session, lib_common.MakeProp("Program"), lib_util.NodeLiteral(sess_program)))

        if schema_name != None:
            node_schema = oracle_schema.MakeUri(cgiEnv.m_oraDatabase, str(schema_name))
            grph.add((node_session, pc.property_oracle_schema, node_schema))
            grph.add((node_oradb, pc.property_oracle_db, node_schema))

        logging.debug("user_proc_id=%s user_machine=%s", user_proc_id, user_machine)
        node_process = the_machine_box.PidUri(sess_pid)
        grph.add((node_process, lib_common.MakeProp("SystemPid"), lib_util.NodeLiteral(user_proc_id)))
        grph.add((node_process, lib_common.MakeProp("OraclePid"), lib_util.NodeLiteral(process_pid)))
        grph.add((node_process, lib_common.MakeProp("Terminal"), lib_util.NodeLiteral(proc_terminal)))
        grph.add((node_session, pc.property_oracle_session, node_process))

        if sess_osuser != None:
            logging.debug("user_machine=%s sess_osuser=%s", user_machine, sess_osuser)
            node_os_user = the_machine_box.UserUri(sess_osuser)
            grph.add((node_os_user, lib_common.MakeProp("OsUser"), lib_util.NodeLiteral(sess_osuser)))
            grph.add((node_process, pc.property_user, node_os_user))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
