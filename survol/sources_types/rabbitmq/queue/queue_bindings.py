#!/usr/bin/env python

"""
RabbitMQ queue bindings
"""

import sys
import logging
import lib_util
import lib_common
import lib_credentials
from pyrabbit.api import Client
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
    nam_queue = cgiEnv.m_entity_id_dict["Queue"]

    node_manager = survol_rabbitmq_manager.MakeUri(config_nam)

    creds = lib_credentials.GetCredentials("RabbitMQ", config_nam )

    # cl = Client('localhost:12345', 'guest', '*****')
    cl = Client(config_nam, creds[0], creds[1])

    grph = cgiEnv.GetGraph()

    nod_v_host = survol_rabbitmq_vhost.MakeUri(config_nam, nam_v_host)
    grph.add((node_manager, lib_common.MakeProp("virtual host node"), nod_v_host))

    node_queue = survol_rabbitmq_queue.MakeUri(config_nam, nam_v_host, nam_queue)
    grph.add((nod_v_host, lib_common.MakeProp("Queue"), node_queue))

    # >>> cl.get_queue_bindings("/","aliveness-test")
    # [{u'vhost': u'/', u'properties_key': u'aliveness-test', u'destination': u'aliveness-test', u'routing_key': u'aliveness-test', u'sour
    # ce': u'', u'arguments': {}, u'destination_type': u'queue'}]
    lst_bindings = cl.get_queue_bindings(nam_v_host, nam_queue)

    for sublst_bindings in lst_bindings:
        for key_bindings in sublst_bindings:
            val_bindings = sublst_bindings[key_bindings]
            str_disp = str(val_bindings).replace("{", "").replace("}", "")
            grph.add((node_queue, lib_common.MakeProp(key_bindings), lib_util.NodeLiteral(str_disp)))
            logging.debug("key_bindings=%s val_bindings=%s", key_bindings, val_bindings)

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
