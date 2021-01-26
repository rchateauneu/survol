#!/usr/bin/env python

"""
Databases in a MySql instance
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
from sources_types.mysql import database as survol_mysql_database
from sources_types.mysql import instance as survol_mysql_instance


def Main():
    cgiEnv = lib_common.CgiEnv( )

    instance_name = cgiEnv.m_entity_id_dict["Instance"]
    instance_node = survol_mysql_instance.MakeUri(instance_name)

    hostname, hostport = survol_mysql.InstanceToHostPort(instance_name)

    cgiEnv = lib_common.CgiEnv()

    grph = cgiEnv.GetGraph()

    # BEWARE: The rule whether we use the host name or the host IP is not very clear !
    # The IP address would be unambiguous but less clear.
    host_node = lib_common.gUriGen.HostnameUri(hostname)

    prop_db = lib_common.MakeProp("Mysql database")

    a_cred = lib_credentials.GetCredentials("MySql", instance_name)

    # If user/password incorrect, nothing we can do.
    try:
        a_user = a_cred[0]
        conn_mysql = survol_mysql.MysqlConnect(instance_name, a_user, aPass=a_cred[1])
    except Exception as exc:
        lib_common.ErrorMessageHtml("Cannot connect to instance=%s user=%s:%s" % (instance_name, a_user, str(exc)))

    cursor_mysql = conn_mysql.cursor()

    cursor_mysql.execute("show databases")

    grph.add((host_node, lib_common.MakeProp("Mysql instance"), instance_node))

    for db_info in cursor_mysql:
        #('information_schema',)
        #('primhilltcsrvdb1',)
        logging.debug("db_info=%s", str(db_info))
        db_nam = db_info[0]

        node_mysql_database = survol_mysql_database.MakeUri(instance_name, db_nam)

        # Create a node for each database.
        user_node = lib_common.gUriGen.UserUri(a_cred[0])
        grph.add((node_mysql_database, pc.property_user, user_node))
        grph.add((instance_node, prop_db, node_mysql_database))

    cursor_mysql.close()
    conn_mysql.close()

    cgiEnv.OutCgiRdf("LAYOUT_SPLINE")


if __name__ == '__main__':
    Main()
