#!/usr/bin/env python

"""
Sends one event per second. Test purpose.
"""

import os
import sys
import time
import datetime
import rdflib

import lib_util
import lib_common
import lib_properties
from lib_properties import pc

_param_a = "parama"
_param_b = "paramb"


def Snapshot():
    cgiEnv = lib_common.CgiEnv(parameters={_param_a: 1, _param_b: "Two"})

    # This is to ensure that all CGI parameters are handled.
    parameter_a = int(cgiEnv.get_parameters(_param_a))
    parameter_b = cgiEnv.get_parameters(_param_b)

    grph = cgiEnv.ReinitGraph()

    current_pid = os.getpid()
    node_process = lib_common.gUriGen.PidUri(current_pid)

    param_a_property = lib_properties.MakeProp(_param_a)
    param_b_property = lib_properties.MakeProp(_param_b)

    sample_node = rdflib.BNode()

    # TODO: pc.property_information is the default property for sorting by time-stamp.
    # TODO: This could use a specififc timestamp property, for example "point in time" P585
    datetime_now = datetime.datetime.now()
    timestamp_literal = datetime_now.strftime("%Y-%m-%d %H:%M:%S")
    grph.add((sample_node, pc.property_information, lib_util.NodeLiteral(timestamp_literal)))

    grph.add((sample_node, param_a_property, lib_util.NodeLiteral(parameter_a)))
    grph.add((sample_node, param_b_property, lib_util.NodeLiteral(parameter_b)))

    grph.add((node_process, lib_properties.MakeProp("sample"), sample_node))

    cgiEnv.OutCgiRdf()


def Main():
    if lib_util.is_snapshot_behaviour():
        Snapshot()
    else:
        while True:
            Snapshot()
            time.sleep(1)


if __name__ == '__main__':
    Main()

