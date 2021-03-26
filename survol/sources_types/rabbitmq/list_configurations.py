#!/usr/bin/env python

"""
List available RabbitMQ configurations
Configurations detected in the private credentials file.
"""

import sys
import logging

import lib_uris
import lib_common
import lib_util
import lib_credentials

from sources_types import rabbitmq
from sources_types.rabbitmq import manager as survol_rabbitmq_manager


def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    #"RabbitMQ" : {
    #    "localhost:12345" : [ "guest", "*********" ]
    #    }
    cred_list = lib_credentials.get_credentials_names("RabbitMQ")

    grph = cgiEnv.GetGraph()

    if cred_list:
        for config_nam in cred_list:

            # Nothing else but a host and a port. The host is case insensitive: RFC4343.
            config_nam = config_nam.lower()

            logging.debug("config_nam=%s", config_nam)
            node_manager = survol_rabbitmq_manager.MakeUri(config_nam)

            host_split = config_nam.split(":")

            if len(host_split) < 2:
                lib_common.ErrorMessageHtml("RabbitMQ configuration. Port number not defined:%s" % config_nam)

            node_addr = lib_uris.gUriGen.AddrUri(host_split[0], host_split[1])

            grph.add((node_addr, lib_common.MakeProp("RabbitMQ manager"), node_manager))

            # http://127.0.0.1:12345/#/
            management_url = rabbitmq.ManagementUrlPrefix(config_nam)
            grph.add((node_addr, lib_common.MakeProp("Management"), lib_common.NodeUrl(management_url)))

            # TODO: Get and display the log files.
            # Config file     c:/Users/jsmith/AppData/Roaming/RabbitMQ/rabbitmq.config
            # Database directory     c:/Users/jsmith/AppData/Roaming/RabbitMQ/db/RABBIT~1
            # Log file     C:/Users/jsmith/AppData/Roaming/RabbitMQ/log/RABBIT~1.LOG
            # SASL log file     C:/Users/jsmith/AppData/Roaming/RabbitMQ/log/RABBIT~2.LOG

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
