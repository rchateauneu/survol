#!/usr/bin/env python

"""
RabbitMQ virtual hosts queues
"""

import sys
import logging
import lib_common
import lib_credentials
from pyrabbit.api import Client
from sources_types import rabbitmq
from sources_types.rabbitmq import manager as survol_rabbitmq_manager
from sources_types.rabbitmq import queue as survol_rabbitmq_queue
from sources_types.rabbitmq import vhost as survol_rabbitmq_vhost

# It uses the port of the management interface:
# In rabbitmq.config:
# {rabbitmq_management,
#  [
#   {listener, [{port,     12345},
#               {ip,       "127.0.0.1"}]}

# rabbitmq-plugins enable rabbitmq_management


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

    for qu_list in cl.get_queues(nam_v_host):
        nam_queue = qu_list["name"]
        logging.debug("q=%s", nam_queue)

        node_queue = survol_rabbitmq_queue.MakeUri(config_nam, nam_v_host, nam_queue)

        management_url = rabbitmq.ManagementUrlPrefix(config_nam, "queues", nam_v_host, nam_queue)

        grph.add((node_queue, lib_common.MakeProp("Management"), lib_common.NodeUrl(management_url)))

        grph.add((nod_v_host, lib_common.MakeProp("Queue"), node_queue))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
