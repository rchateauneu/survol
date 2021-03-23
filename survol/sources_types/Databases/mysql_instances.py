#!/usr/bin/env python

"""
mysql instances
"""

# This lists MySQL servers from the credentials list.
# It does not attempt to connect to a server,
# and therefore does not need the appropriate packages.
# TODO: Detect servers with nmap.

import os
import sys
import re
import logging

import lib_uris
import lib_util
import lib_common
import lib_credentials
from lib_properties import pc

# This does not import genuine mysql packages so this will always work.
from sources_types.mysql import instance as survol_mysql_instance


def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    grph = cgiEnv.GetGraph()

    cred_names = lib_credentials.get_credentials_names("MySql")
    logging.debug("Mysql servers")

    for instance_my_sql in cred_names:
        logging.debug("MySql servers instance_my_sql=%s", instance_my_sql)

        # Do not use sources_types.mysql
        host_my_sql = instance_my_sql.split(":")[0]

        # TODO: Display the connection socket ?
        node_host_my_sql = lib_uris.gUriGen.HostnameUri(host_my_sql)

        node_instance = survol_mysql_instance.MakeUri(instance_my_sql)

        a_cred = lib_credentials.GetCredentials("MySql", instance_my_sql)

        grph.add((node_instance, lib_common.MakeProp("Mysql user"), lib_util.NodeLiteral(a_cred[0])))
        grph.add((node_instance, lib_common.MakeProp("Mysql instance"), node_host_my_sql))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
