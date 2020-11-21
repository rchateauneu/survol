import lib_common
from lib_properties import pc

# TODO: This file should go to sources_types/oracle

import sys
import re
import lib_util
import lib_credentials

from sources_types.oracle import table as oracle_table
from sources_types.oracle import view as oracle_view
from sources_types.oracle import package as oracle_package
from sources_types.oracle import package_body as oracle_package_body

from sources_types.oracle import function as oracle_function
from sources_types.oracle import library as oracle_library
from sources_types.oracle import procedure as oracle_procedure
from sources_types.oracle import sequence as oracle_sequence
from sources_types.oracle import synonym as oracle_synonym
from sources_types.oracle import trigger as oracle_trigger
from sources_types.oracle import type as oracle_type

# http://stackoverflow.com/questions/13589683/interfaceerror-unable-to-acquire-oracle-environment-handle-oracle-home-is-corr
# InterfaceError: Unable to acquire Oracle environment handle

import cx_Oracle


def GetOraConnect(conn_str):
    try:
        return cx_Oracle.connect(conn_str)
    # except cx_Oracle.InterfaceError:
    # except cx_Oracle.DatabaseError:
    except Exception as exc:
        secure_connect_str = re.sub("/[^@]*", "/********", conn_str)
        lib_common.ErrorMessageHtml("cx_Oracle.connect conn_str=%s Err=%s " % (secure_connect_str, str(exc)))


# TODO: Check that there is only one query, and exclusively a select, to avoid SQL injections.
def _execute_safe_query(a_cursor, sql_query):
    if not sql_query.strip().upper().startswith("SELECT "):
        raise Exception("Unsafe query:%s"%sql_query)
    a_cursor.execute(sql_query)


def OracleConnectionClose(conn):
    try:
        conn.close()
    except cx_Oracle.DatabaseError as exc:
        # "connection cannot be closed when open statements or LOBs exist"
        # cx_oracle throws "DPI-1054: connection cannot be closed when open statements or LOBs exist" during django migration
        err_msg = str(exc)
        if err_msg.find("connection cannot be closed when open statements") >= 0:
            WARNING("OracleConnectionClose LOBs exist: exception:%s.", err_msg)
            pass
        else:
            lib_common.ErrorMessageHtml("OracleConnectionClose caught:%s."% (err_msg))


def ExecuteQueryThrow(conn_str, sql_query):
    result = []
    conn = GetOraConnect(conn_str)
    a_cursor = conn.cursor()

    DEBUG("ExecuteQuery %s", sql_query)

    _execute_safe_query(a_cursor, sql_query)
    try:
        # This could be faster by returning a cursor
        # or a generator, but this is not important now.
        for row in a_cursor:
            # Use yield ? Or return c ?
            result.append(row)

    except cx_Oracle.DatabaseError:
        pass
    OracleConnectionClose(conn)

    return result


def ExecuteQuery(conn_str, sql_query):
    try:
        return ExecuteQueryThrow(conn_str, sql_query)
    except cx_Oracle.DatabaseError as exc:
        lib_common.ErrorMessageHtml("ExecuteQuery exception:%s in %s" % (str(exc), sql_query))


def CallbackQuery(conn_str, sql_query, the_callback):
    """Faster because no object copy, and also mandatory if LOBs are returned,
    because they disappear when the cursor is deleted."""
    conn = GetOraConnect(conn_str)

    a_cursor = conn.cursor()

    _execute_safe_query(a_cursor, sql_query)
    try:
        for row in a_cursor:
            the_callback(row)
    except cx_Oracle.DatabaseError:
        pass
    OracleConnectionClose(conn)


# BEWARE: There is an implicit dependency on the structure of Oracle schema URI.
# https://docs.oracle.com/cd/A91202_01/901_doc/server.901/a90125/sql_elements10.htm
# CREATE SYNONYM emp_table FOR oe.employees@remote.us.oracle.com;
# schema.object_name.object_part@dblink

class OracleEnv (lib_common.CgiEnv):
    def __init__(self):
        lib_common.CgiEnv.__init__(self)

        self.m_oraDatabase = self.m_entity_id_dict["Db"]

    def ConnectStr(self):
        # TODO: This can be parsed from the schema.

        ora_user, ora_pwd = lib_credentials.GetCredentials("Oracle", self.m_oraDatabase)
        return ora_user + "/" + ora_pwd + "@" + self.m_oraDatabase

    def MakeUri(self, entity_type, **kwArgs):
        return lib_util.EntityUri(entity_type, {"Db": self.m_oraDatabase}, **kwArgs)

    def OracleSchema(self):
        # TODO: This could call GetCredentials once only.
        ora_user, ora_pwd = lib_credentials.GetCredentials("Oracle", self.m_oraDatabase)
        return ora_user


_oracle_type_name_to_class = {
    "TABLE": oracle_table,
    "VIEW": oracle_view,
    "PACKAGE": oracle_package,
    "PACKAGE BODY": oracle_package_body,
    "SYNONYM": oracle_synonym,
    "TYPE": oracle_type,
    "SEQUENCE": oracle_sequence,
    "LIBRARY": oracle_library,
    "PROCEDURE": oracle_procedure,
    "FUNCTION": oracle_function,
    "TRIGGER": oracle_trigger}


def AddDependency(grph, row, node_root, ora_database, direction):
    """This displays the content of one row of the Oracle table dba_dependencies."""
    dep_owner = str(row[0])
    dep_name = str(row[1])
    dep_type = str(row[2])

    try:
        the_oracle_class = _oracle_type_name_to_class[dep_type]
    except KeyError:
        lib_common.ErrorMessageHtml("Unknown dependency dep_type=%s dep_name=%s" % (dep_type, dep_name))
        return

    node_object = the_oracle_class.MakeUri(ora_database, dep_owner, dep_name)

    if direction:
        grph.add((node_root, pc.property_oracle_depends, node_object))
    else:
        grph.add((node_object, pc.property_oracle_depends, node_root))


def AddLiteralNotNone(grph, node, txt, data):
    if data != None:
        grph.add((node, lib_util.MakeProp(txt), lib_util.NodeLiteral(data)))


def OraMachineToIp(ora_machine):
    """This returns an IP address."""
    # Maybe different on Linux ???  "WORKGROUP\RCHATEAU-HP"
    user_machine = lib_util.GlobalGetHostByName(ora_machine.split("\\")[-1])
    return user_machine
