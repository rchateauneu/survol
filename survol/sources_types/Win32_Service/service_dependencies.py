#!/usr/bin/env python

"""
Windows service dependencies
"""

import os
import sys
import logging
import lib_util
import lib_common
from lib_properties import pc

import time
import datetime
from sources_types import Win32_Service

Usable = lib_util.UsableWindows


def TimeStamp():
    ts = time.time()
    return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S') + ":"


def Main():
    cgiEnv = lib_common.ScriptEnvironment(can_process_remote=True)
    service_name = cgiEnv.GetId()
    service_host = cgiEnv.GetHost()
    grph = cgiEnv.GetGraph()

    logging.debug("service_name=%s", service_name)

    # Unfortunately we build the complete network for just one service.
    dict_service_map = Win32_Service.BuildSrvNetwork(service_host)

    # FIXME: Do not print str(dict_service_map) because it hangs.
    logging.debug(TimeStamp()+ "service_name=%s dict_service_map=%s", service_name, "str(dict_service_map)")

    service_dict = dict_service_map[service_name]

    service_node = Win32_Service.DictServiceToNode(grph, service_dict, service_host)

    # There should not be any circular dependency, so no need to create the dependent nodes in advance.
    for sub_service_name_in in service_dict["depends_in"]:
        sub_service_dict_in = dict_service_map[ sub_service_name_in ]
        sub_service_node_in = Win32_Service.DictServiceToNode(grph, sub_service_dict_in, service_host)
        grph.add((service_node, pc.property_service, sub_service_node_in))

    for sub_service_name_out in service_dict["depends_out"]:
        sub_service_dict_out = dict_service_map[sub_service_name_out]
        sub_service_node_out = Win32_Service.DictServiceToNode(grph, sub_service_dict_out, service_host)
        grph.add((sub_service_node_out, pc.property_service, service_node))

    # TODO: Edges should be better displayed. Change colors, more informaiton in the name.
    # TODO Also, they could be bidirectional, have more informaiton in the name.
    # TODO: Add attributes to the URL, for example:
    # TODO: Type;Titre;Couleur;Taille;Fleches
    # TODO: sub-process;Pid=123;Red:1;SinpleArrow
    # TODO: socket;Telnet;Green;BidirectionnalArrow

    cgiEnv.OutCgiRdf("LAYOUT_SPLINE")


if __name__ == '__main__':
    Main()
