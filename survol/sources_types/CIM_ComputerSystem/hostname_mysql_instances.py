#!/usr/bin/env python

"""
mysql instances on a server
"""

import sys
import re
import socket

import lib_uris
import lib_util
import lib_common
import lib_credentials
from lib_properties import pc

# This does not import genuine mysql packages so this will always work.
from sources_types.mysql import instance as survol_mysql_instance


def Main():
    cgiEnv = lib_common.ScriptEnvironment()
    hostname = cgiEnv.GetId()

    host_addr = lib_util.GlobalGetHostByName(hostname)
    host_node = lib_uris.gUriGen.HostnameUri(hostname)

    cgiEnv = lib_common.ScriptEnvironment()

    grph = cgiEnv.GetGraph()

    prop_instance = lib_common.MakeProp("Mysql instance")

    # Now it looks for Mysql instances which are hosted on this machine.
    cred_list = lib_credentials.get_credentials_names("MySql")
    for instance_name in cred_list:
        # This does not even need mysql package, so it can always detect instances.
        sql_inst_host = instance_name.split(":")[0].strip()

        if (sql_inst_host != hostname) and (sql_inst_host != host_addr):
            sql_inst_addr = lib_util.GlobalGetHostByName(sql_inst_host)
            if (sql_inst_addr != hostname) and (sql_inst_addr != host_addr):
                continue

        # Intentionaly, it does not use mysql package.
        node_instance = survol_mysql_instance.MakeUri(instance_name)

        grph.add((host_node, prop_instance, node_instance))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
