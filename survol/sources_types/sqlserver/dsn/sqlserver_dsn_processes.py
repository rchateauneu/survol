#!/usr/bin/env python

# Display processes running in this database.

"""
Processes running in SQL Server database (ODBC)
"""

import sys
import logging
import lib_util
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
    cgiEnv = lib_common.ScriptEnvironment()

    grph = cgiEnv.GetGraph()

    dsn_nam = survol_odbc_dsn.GetDsnNameFromCgi(cgiEnv)

    logging.debug("dsn=(%s)", dsn_nam)

    node_dsn = survol_sqlserver_dsn.MakeUri(dsn_nam)

    ODBC_ConnectString = survol_odbc_dsn.MakeOdbcConnectionString(dsn_nam)
    try:
        cnxn = pyodbc.connect(ODBC_ConnectString)
        logging.debug("Connected: %s", dsn_nam)
        cursor_sessions = cnxn.cursor()

        qry_sessions = """
        SELECT host_name,host_process_id,session_id,program_name,client_interface_name,original_login_name,nt_domain,nt_user_name
        FROM sys.dm_exec_sessions where host_process_id is not null
        """

        prop_sql_server_session = lib_common.MakeProp("SqlServer session")
        prop_sql_server_host_process = lib_common.MakeProp("Host process")
        prop_sql_server_program_name = lib_common.MakeProp("Program name")
        prop_sql_server_client_interface = lib_common.MakeProp("Client Interface")

        prop_sql_server_original_login_name = lib_common.MakeProp("original_login_name")
        prop_sql_server_nt_domain = lib_common.MakeProp("nt_domain")
        prop_sql_server_nt_user_name = lib_common.MakeProp("nt_user_name")

        for row_sess in cursor_sessions.execute(qry_sessions):
            logging.debug("row_sess.session_id=(%s)", row_sess.session_id)
            node_session = session.MakeUri(dsn_nam, row_sess.session_id)
            grph.add((node_dsn, prop_sql_server_session, node_session))

            node_process = lib_common.RemoteBox(row_sess.host_name).PidUri(row_sess.host_process_id)
            grph.add((node_process, pc.property_pid, lib_util.NodeLiteral(row_sess.host_process_id)))

            grph.add((node_session, prop_sql_server_host_process, node_process))
            grph.add((node_session, prop_sql_server_program_name, lib_util.NodeLiteral(row_sess.program_name)))
            grph.add((node_session, prop_sql_server_client_interface, lib_util.NodeLiteral(row_sess.client_interface_name)))

            # TODO: Make nodes with these:

            grph.add(
                (node_session, prop_sql_server_original_login_name, lib_util.NodeLiteral(row_sess.original_login_name)))
            grph.add((node_session, prop_sql_server_nt_domain, lib_util.NodeLiteral(row_sess.nt_domain)))
            grph.add((node_session, prop_sql_server_nt_user_name, lib_util.NodeLiteral(row_sess.nt_user_name)))

    except Exception as exc:
        lib_common.ErrorMessageHtml(
            "node_dsn=%s Unexpected error:%s" % (dsn_nam, str(sys.exc_info())))  # cgiEnv.OutCgiRdf()

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()

# http://www.easysoft.com/developer/languages/python/pyodbc.html
