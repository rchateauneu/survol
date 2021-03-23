#!/usr/bin/env python

"""
Mysql table information
"""

import sys
import re
import socket
import logging

import lib_uris
import lib_util
import lib_common
import lib_credentials
from lib_properties import pc

from sources_types import mysql as survol_mysql
from sources_types.mysql import database as survol_mysql_database
from sources_types.mysql import table as survol_mysql_table


def Main():

    cgiEnv = lib_common.ScriptEnvironment( )

    instance_name = cgiEnv.m_entity_id_dict["Instance"]
    db_nam = cgiEnv.m_entity_id_dict["Database"]
    table_nam = cgiEnv.m_entity_id_dict["Table"]

    hostname, hostport = survol_mysql.InstanceToHostPort(instance_name)

    cgiEnv = lib_common.ScriptEnvironment()

    grph = cgiEnv.GetGraph()

    host_node = lib_uris.gUriGen.HostnameUri(hostname)

    # BEWARE: This is duplicated.
    prop_db = lib_common.MakeProp("Mysql database")

    node_mysql_database = survol_mysql_database.MakeUri(instance_name, db_nam)
    grph.add((host_node, prop_db, node_mysql_database))

    a_cred = lib_credentials.GetCredentials("MySql", instance_name)

    conn_mysql = survol_mysql.MysqlConnect(instance_name, aUser=a_cred[0], aPass=a_cred[1])

    cursor_mysql = conn_mysql.cursor()

    cursor_mysql.execute(
        "select * from information_schema.TABLES where TABLE_SCHEMA='%s' and TABLE_NAME='%s'"
        % (db_nam.upper(),table_nam.upper()))

    prop_table = lib_common.MakeProp("Mysql table")

    # TABLE_CATALOG         def
    # TABLE_SCHEMA    Table_...
    # TABLE_NAME    Table_...
    # TABLE_TYPE
    # ENGINE    Engine    MySQL extension
    # VERSION    Version    The version number of the table's .frm file, MySQL extension
    # ROW_FORMAT    Row_format    MySQL extension
    # TABLE_ROWS    Rows    MySQL extension
    # AVG_ROW_LENGTH    Avg_row_length    MySQL extension
    # DATA_LENGTH    Data_length    MySQL extension
    # MAX_DATA_LENGTH    Max_data_length    MySQL extension
    # INDEX_LENGTH    Index_length    MySQL extension
    # DATA_FREE    Data_free    MySQL extension
    # AUTO_INCREMENT    Auto_increment    MySQL extension
    # CREATE_TIME    Create_time    MySQL extension
    # UPDATE_TIME    Update_time    MySQL extension
    # CHECK_TIME    Check_time    MySQL extension
    # TABLE_COLLATION    Collation    MySQL extension
    # CHECKSUM    Checksum    MySQL extension
    # CREATE_OPTIONS    Create_options    MySQL extension
    # TABLE_COMMENT    Comment    MySQL extension

    # ...     print(x)
    # (    'def', 'primhilltcsrvdb1', 'Test_Table', 'BASE TABLE', 'InnoDB',
    #    10L, 'Compact', 2L, 8192L, 16384L,
    #    0L, 0L, 0L, None, datetime.datetime(2017, 12, 13, 8, 59, 24),
    #    None, None, 'latin1_swedish_ci', None, '',
    #    'Comment about this test table.')

    # There should be only one row, maximum.
    for tab_info in cursor_mysql:
        logging.debug("tab_info=%s", str(tab_info))
        table_nam = tab_info[2]

        node_mysql_table = survol_mysql_table.MakeUri(hostname,db_nam, table_nam)

        grph.add((node_mysql_table, lib_common.MakeProp("Table type"), lib_util.NodeLiteral(tab_info[3])))
        grph.add((node_mysql_table, lib_common.MakeProp("Engine"), lib_util.NodeLiteral(tab_info[4])))
        grph.add((node_mysql_table, lib_common.MakeProp("Version"), lib_util.NodeLiteral(tab_info[5])))
        grph.add((node_mysql_table, lib_common.MakeProp("Row format"), lib_util.NodeLiteral(tab_info[6])))
        grph.add((node_mysql_table, lib_common.MakeProp("Table rows"), lib_util.NodeLiteral(tab_info[7])))
        grph.add((node_mysql_table, lib_common.MakeProp("Average row length"), lib_util.NodeLiteral(tab_info[8])))
        grph.add((node_mysql_table, lib_common.MakeProp("Data length"), lib_util.NodeLiteral(tab_info[9])))
        grph.add((node_mysql_table, lib_common.MakeProp("Maximum data length"), lib_util.NodeLiteral(tab_info[10])))
        grph.add((node_mysql_table, lib_common.MakeProp("Index length"), lib_util.NodeLiteral(tab_info[11])))
        grph.add((node_mysql_table, lib_common.MakeProp("Data free"), lib_util.NodeLiteral(tab_info[12])))
        grph.add((node_mysql_table, lib_common.MakeProp("Auto increment"), lib_util.NodeLiteral(tab_info[13])))
        grph.add((node_mysql_table, lib_common.MakeProp("Creation time"), lib_util.NodeLiteral(tab_info[14])))
        grph.add((node_mysql_table, lib_common.MakeProp("Update time"), lib_util.NodeLiteral(tab_info[15])))
        grph.add((node_mysql_table, lib_common.MakeProp("Check time"), lib_util.NodeLiteral(tab_info[16])))
        grph.add((node_mysql_table, lib_common.MakeProp("Table collation"), lib_util.NodeLiteral(tab_info[17])))
        grph.add((node_mysql_table, lib_common.MakeProp("Checksum"), lib_util.NodeLiteral(tab_info[18])))
        grph.add((node_mysql_table, lib_common.MakeProp("Create options"), lib_util.NodeLiteral(tab_info[19])))
        grph.add((node_mysql_table, pc.property_information, lib_util.NodeLiteral(tab_info[20])))

        grph.add((node_mysql_database, prop_table, node_mysql_table))

    cursor_mysql.close()
    conn_mysql.close()

    cgiEnv.OutCgiRdf("LAYOUT_RECT_TB")


if __name__ == '__main__':
    Main()
