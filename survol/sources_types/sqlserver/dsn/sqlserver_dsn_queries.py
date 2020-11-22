#!/usr/bin/env python

"""
Queries running in SQL Server database (ODBC)
"""

import sys
import lib_util
import lib_common
from lib_properties import pc
from sources_types.odbc import dsn as survol_odbc_dsn
from sources_types.sqlserver import dsn as survol_sqlserver_dsn
from sources_types.sqlserver import session
from sources_types.sqlserver import query as sql_query


try:
    import pyodbc
except ImportError:
    lib_common.ErrorMessageHtml("pyodbc Python library not installed")


def Main():
    cgiEnv = lib_common.CgiEnv()

    grph = cgiEnv.GetGraph()

    dsn_nam = survol_odbc_dsn.GetDsnNameFromCgi(cgiEnv)

    DEBUG("dsn=(%s)", dsn_nam)

    odbc_connect_string = survol_odbc_dsn.MakeOdbcConnectionString(dsn_nam)
    try:
        cnxn = pyodbc.connect(odbc_connect_string)
        DEBUG("Connected: %s", dsn_nam)
        cursor_queries = cnxn.cursor()

        qry_queries = """
            SELECT sqltext.TEXT,
            req.session_id,
            req.status,
            sess.host_process_id,
            sess.host_name
            FROM sys.dm_exec_requests req
            CROSS APPLY sys.dm_exec_sql_text(sql_handle) AS sqltext
            , sys.dm_exec_sessions sess
            where sess.session_id = req.session_id
        """

        prop_sql_server_sql_query = lib_common.MakeProp("Sql query")
        prop_sql_server_host_process = lib_common.MakeProp("Host process")
        prop_sql_server_status = lib_common.MakeProp("Status")

        for row_qry in cursor_queries.execute(qry_queries):
            DEBUG("row_qry.session_id=(%s)", row_qry.session_id)
            node_session = session.MakeUri(dsn_nam, row_qry.session_id)

            # A bit of cleanup.
            query_clean = row_qry.TEXT.replace("\n", " ").strip()

            # TODO: Must add connection information so we can go from the tables to sqlserver itself.
            node_sql_query = sql_query.MakeUri(query_clean,dsn_nam)
            grph.add((node_session, prop_sql_server_sql_query, node_sql_query))
            node_process = lib_common.RemoteBox(row_qry.host_name).PidUri(row_qry.host_process_id)
            grph.add((node_process, pc.property_pid, lib_util.NodeLiteral(row_qry.host_process_id)))

            grph.add((node_session, prop_sql_server_host_process, node_process))
            grph.add((node_session, prop_sql_server_status, lib_util.NodeLiteral(row_qry.status)))

    except Exception as exc:
        lib_common.ErrorMessageHtml(
            "nodeDsn=%s Unexpected error:%s" % (dsn_nam, str(exc)))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()

# http://www.easysoft.com/developer/languages/python/pyodbc.html
