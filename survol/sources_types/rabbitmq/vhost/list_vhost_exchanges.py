#!/usr/bin/env python

"""
RabbitMQ virtual hosts exchanges
"""

import sys
import logging

import lib_common
import lib_credentials
from pyrabbit.api import Client
from sources_types import rabbitmq
from sources_types.rabbitmq import manager as survol_rabbitmq_manager
from sources_types.rabbitmq import exchange as survol_rabbitmq_exchange
from sources_types.rabbitmq import vhost as survol_rabbitmq_vhost


def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    config_nam = cgiEnv.m_entity_id_dict["Url"]
    nam_v_host = cgiEnv.m_entity_id_dict["VHost"]

    node_manager = survol_rabbitmq_manager.MakeUri(config_nam)

    creds = lib_credentials.GetCredentials("RabbitMQ", config_nam)

    # cl = Client('localhost:12345', 'guest', '*****')
    cl = Client(config_nam, creds[0], creds[1])

    grph = cgiEnv.GetGraph()

    nod_v_host = survol_rabbitmq_vhost.MakeUri(config_nam, nam_v_host)
    grph.add((node_manager, lib_common.MakeProp("virtual host node"), nod_v_host))

    for obj_exchange in cl.get_exchanges(nam_v_host):
        nam_exchange = obj_exchange["name"]
        logging.debug("nam_exchange=%s", nam_exchange)

        node_exchange = survol_rabbitmq_exchange.MakeUri(config_nam, nam_v_host, nam_exchange)

        management_url = rabbitmq.ManagementUrlPrefix(config_nam, "exchanges", nam_v_host, nam_exchange)

        grph.add((node_exchange, lib_common.MakeProp("Management"), lib_common.NodeUrl(management_url)))

        grph.add((nod_v_host, lib_common.MakeProp("Exchange"), node_exchange))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
