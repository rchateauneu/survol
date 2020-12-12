#!/usr/bin/env python

"""
Sends one event per second. Test purpose.
"""

import os
import sys
import time
import rdflib

import lib_kbase
import lib_util
import lib_common
import lib_properties
from lib_properties import pc

_param_a = "parama"
_param_b = "paramb"

_global_counter = 1

def Snapshot():
    global _global_counter
    cgiEnv = lib_common.CgiEnv(parameters={_param_a: _global_counter, _param_b: "Two"})

    _global_counter += 1

    # This is to ensure that all CGI parameters are handled.
    parameter_a = int(cgiEnv.get_parameters(_param_a))
    parameter_b = cgiEnv.get_parameters(_param_b)

    grph = cgiEnv.ReinitGraph()

    current_pid = os.getpid()
    node_process = lib_common.gUriGen.PidUri(current_pid)

    param_a_property = lib_properties.MakeProp(_param_a)
    param_b_property = lib_properties.MakeProp(_param_b)

    sample_root_node = rdflib.BNode()

    # TODO: pc.property_information is the default property for sorting by time-stamp.
    # TODO: This could use a specific timestamp property, for example "point in time" P585
    timestamp_node = lib_kbase.time_stamp_now_node()
    grph.add((sample_root_node, pc.property_information, timestamp_node))

    grph.add((sample_root_node, param_a_property, lib_util.NodeLiteral(parameter_a)))
    grph.add((sample_root_node, param_b_property, lib_util.NodeLiteral(parameter_b)))

    property_sample = lib_properties.MakeProp("sample")
    grph.add((node_process, property_sample, sample_root_node))

    cgiEnv.OutCgiRdf("LAYOUT_RECT", [property_sample])


def Main():
    if lib_util.is_snapshot_behaviour():
        Snapshot()
    else:
        while True:
            Snapshot()
            time.sleep(1)


if __name__ == '__main__':
    Main()

