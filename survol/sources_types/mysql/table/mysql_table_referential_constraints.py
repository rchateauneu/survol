#!/usr/bin/env python

"""
Referential constraints
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

# mysql> select * from information_schema.referential_constraints;
# +--------------------+-------------------+---------------------------+---------------------------+--------------------------+-------
# -----------------+--------------+-------------+-------------+-----------------+-----------------------+
# | CONSTRAINT_CATALOG | CONSTRAINT_SCHEMA | CONSTRAINT_NAME           | UNIQUE_CONSTRAINT_CATALOG | UNIQUE_CONSTRAINT_SCHEMA | UNIQUE
# _CONSTRAINT_NAME | MATCH_OPTION | UPDATE_RULE | DELETE_RULE | TABLE_NAME      | REFERENCED_TABLE_NAME |
# +--------------------+-------------------+---------------------------+---------------------------+--------------------------+-------
# -----------------+--------------+-------------+-------------+-----------------+-----------------------+
# | def                | sakila            | fk_address_city           | def                       | sakila                   | PRIMAR
# Y                | NONE         | CASCADE     | RESTRICT    | address         | city                  |


def Main():

    cgiEnv = lib_common.ScriptEnvironment( )

    instance_name = cgiEnv.m_entity_id_dict["Instance"]
    db_nam = cgiEnv.m_entity_id_dict["Database"].upper()
    table_nam = cgiEnv.m_entity_id_dict["Table"].upper()

    hostname, hostport = survol_mysql.InstanceToHostPort(instance_name)

    cgiEnv = lib_common.ScriptEnvironment()

    grph = cgiEnv.GetGraph()

    hostAddr = lib_util.GlobalGetHostByName(hostname)

    # BEWARE: The rule whether we use the host name or the host IP is not very clear !
    # The IP address would be unambiguous but less clear.
    host_node = lib_uris.gUriGen.HostnameUri(hostname)

    # BEWARE: This is duplicated.
    prop_db = lib_common.MakeProp("Mysql database")

    node_mysql_database = survol_mysql_database.MakeUri(instance_name, db_nam)
    grph.add((host_node, prop_db, node_mysql_database))

    a_cred = lib_credentials.GetCredentials("MySql", instance_name)

    prop_table = lib_common.MakeProp("Mysql table")
    prop_constraint = lib_common.MakeProp("Table type")

    conn_mysql = survol_mysql.MysqlConnect(instance_name, aUser=a_cred[0], aPass=a_cred[1])

    cursor_mysql = conn_mysql.cursor()

    cursor_mysql.execute("select TABLE_NAME, REFERENCED_TABLE_NAME from information_schema.referential_constraints"
    " where CONSTRAINT_SCHEMA='%s' "
    " and ( TABLE_NAME='%s' or REFERENCED_TABLE_NAME='%s' ) " % (db_nam,table_nam,table_nam))

    # There should be only one row, maximum.
    for constraint_info in cursor_mysql:
        logging.debug("constraint_info=%s", str(constraint_info))
        table_nam = constraint_info[0]
        table_nam_ref = constraint_info[1]
        logging.debug("table_nam=%s", table_nam)

        node_mysql_table = survol_mysql_table.MakeUri(hostname,db_nam, table_nam)
        node_mysql_table_ref = survol_mysql_table.MakeUri(hostname,db_nam, table_nam_ref)

        grph.add((node_mysql_table, prop_constraint, node_mysql_table_ref))

        grph.add((node_mysql_database, prop_table, node_mysql_table))

    cursor_mysql.close()
    conn_mysql.close()

    cgiEnv.OutCgiRdf("LAYOUT_RECT_TB")


if __name__ == '__main__':
    Main()
