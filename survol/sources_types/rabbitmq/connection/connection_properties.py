#!/usr/bin/env python

"""
RabbitMQ connection properties
"""

import sys
import six
import logging

from pyrabbit.api import Client

import lib_uris
import lib_util
import lib_common
import lib_credentials
from lib_properties import pc
from sources_types import rabbitmq
from sources_types.rabbitmq import manager as survol_rabbitmq_manager
from sources_types.rabbitmq import connection as survol_rabbitmq_connection
from sources_types.rabbitmq import vhost as survol_rabbitmq_vhost
from sources_types.rabbitmq import user as survol_rabbitmq_user


def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    config_nam = cgiEnv.m_entity_id_dict["Url"]
    nam_connection = cgiEnv.m_entity_id_dict["Connection"]

    node_manager = survol_rabbitmq_manager.MakeUri(config_nam)

    creds = lib_credentials.GetCredentials("RabbitMQ", config_nam)

    cl = Client(config_nam, creds[0], creds[1])

    grph = cgiEnv.GetGraph()

    logging.debug("nam_connection=%s", nam_connection)

    nod_connection = survol_rabbitmq_connection.MakeUri(config_nam, nam_connection)

    grph.add((node_manager, lib_common.MakeProp("Connection"), nod_connection))

    try:
        connect_list = cl.get_connection(nam_connection)
    except Exception as exc:
        lib_common.ErrorMessageHtml("Caught:" + str(exc))

    for connect_key in connect_list:
        connect_val = connect_list[connect_key]

        if connect_key == "vhost":
            nod_v_host = survol_rabbitmq_vhost.MakeUri(config_nam, connect_val)
            grph.add((nod_connection, lib_common.MakeProp("Virtual host"), nod_v_host))
        elif connect_key == "user":
            nod_user = survol_rabbitmq_user.MakeUri(config_nam, connect_val)
            grph.add((nod_connection, lib_common.MakeProp("User"), nod_user))
        elif connect_key == "host":
            nod_host = lib_uris.gUriGen.HostnameUri(connect_val)
            grph.add((nod_connection, lib_common.MakeProp("Host"), nod_host))
        elif connect_key in ["name", "peer_host", "peer_port"]:
            pass
        else:
            if isinstance(connect_val, six.string_types):
                connect_val = connect_val.replace(">", "@")

                logging.debug("connect_key=%s connect_val=%s", connect_key, connect_val)
            elif isinstance(connect_val, dict):
                pass
            elif isinstance(connect_val, tuple):
                pass
            elif isinstance(connect_val, list):
                pass
            else:
                pass

            logging.debug("Literal=%s", lib_util.NodeLiteral(connect_val))

            grph.add((nod_connection, lib_common.MakeProp(connect_key), lib_util.NodeLiteral(connect_val)))

    survol_rabbitmq_connection.AddSockets(grph, nod_connection, nam_connection)

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
