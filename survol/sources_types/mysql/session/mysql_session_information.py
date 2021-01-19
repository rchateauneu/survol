#!/usr/bin/env python

"""
Information about a mysql session
"""

import sys
import re
import socket
import logging
import lib_util
import lib_common
import lib_credentials

from lib_properties import pc

from sources_types import mysql as survol_mysql
from sources_types.mysql import instance as survol_mysql_instance
from sources_types.mysql import session as survol_mysql_session
from sources_types.mysql import query as survol_mysql_query


def Main():

    cgiEnv = lib_common.CgiEnv( )

    instance_name = cgiEnv.m_entity_id_dict["Instance"]
    session_id = cgiEnv.m_entity_id_dict["Id"]

    instance_node = survol_mysql_instance.MakeUri(instance_name)

    hostname, hostport = survol_mysql.InstanceToHostPort(instance_name)

    cgiEnv = lib_common.CgiEnv()

    grph = cgiEnv.GetGraph()

    # BEWARE: The rule whether we use the host name or the host IP is not very clear !
    # The IP address would be unambiguous but less clear.
    host_node = lib_common.gUriGen.HostnameUri(hostname)

    # BEWARE: This is duplicated.
    propDb = lib_common.MakeProp("Mysql database")

    a_cred = lib_credentials.GetCredentials("MySql", instance_name)

    conn_mysql = survol_mysql.MysqlConnect(instance_name, aUser=a_cred[0], aPass=a_cred[1])

    cursor_mysql = conn_mysql.cursor()

    # mysql> select * from information_schema.processlist;
    # +--------+------------------+------------------+------+---------+------+-----------+----------------------------------------------+
    # | ID     | USER             | HOST             | DB   | COMMAND | TIME | STATE     | INFO                                         |
    # +--------+------------------+------------------+------+---------+------+-----------+----------------------------------------------+
    # | 439768 | primhilltcsrvdb1 | 10.2.123.9:52146 | NULL | Query   |    0 | executing | select * from information_schema.processlist |
    # | 439765 | primhilltcsrvdb1 | 10.2.123.9:52062 | NULL | Sleep   |   13 |           | NULL                                         |
    # +--------+------------------+------------------+------+---------+------+-----------+----------------------------------------------+

    cursor_mysql.execute("select * from information_schema.processlist where ID=%s" % session_id)

    grph.add((host_node, lib_common.MakeProp("Mysql instance"), instance_node))

    # There should be one row only.
    for sess_info in cursor_mysql:
        logging.debug("sess_info=%s", str(sess_info))

        mysql_session_id = sess_info[0]
        mysql_user = sess_info[1]

        session_node = survol_mysql_session.MakeUri(instance_name, mysql_session_id)

        # If there is a proper socket, then create a name for it.
        mysql_socket = sess_info[2]
        try:
            mysql_socket_host, mysql_socket_port = mysql_socket.split(":")
            socket_node = lib_common.gUriGen.AddrUri(mysql_socket_host, mysql_socket_port)
            grph.add((session_node, lib_common.MakeProp("Connection socket"), socket_node))
        except:
            pass

        mysql_db = sess_info[3]
        grph.add((session_node, lib_common.MakeProp("Database"), lib_util.NodeLiteral(mysql_db)))

        mysql_time = sess_info[5]
        grph.add((session_node, lib_common.MakeProp("Time"), lib_util.NodeLiteral(mysql_time)))

        # If there is a running query, then display it.
        mysql_command = sess_info[4]
        mysql_state = sess_info[6]
        if (mysql_command == "Query") and (mysql_state == "executing"):
            mysql_query = sess_info[7]

            node_query = survol_mysql_query.MakeUri(instance_name,mysql_query)
            grph.add((session_node, lib_common.MakeProp("Mysql query"), node_query))

        grph.add((session_node, lib_common.MakeProp("Command"), lib_util.NodeLiteral(mysql_command)))

        grph.add((session_node, lib_common.MakeProp("State"), lib_util.NodeLiteral(mysql_state)))

        grph.add((session_node, lib_common.MakeProp("User"), lib_util.NodeLiteral(mysql_user)))

        grph.add(( session_node, lib_common.MakeProp("Mysql session"), instance_node))

    cursor_mysql.close()
    conn_mysql.close()

    cgiEnv.OutCgiRdf("LAYOUT_SPLINE")


if __name__ == '__main__':
    Main()
