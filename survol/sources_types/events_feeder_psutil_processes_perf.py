#!/usr/bin/env python

"""
Continuous information about running processes.
"""

# This scripts displays information about running processes: CPU, memory etc...
# into a RDF document. It can be processed through the
# RDF "integrator" which should calculate averages and extremums of the CPU and memory loads.


import os
import re
import sys
import time
import psutil
import rdflib

import lib_kbase
import lib_util
import lib_common
from lib_properties import pc
import lib_properties


def Snapshot():
    cgiEnv = lib_common.CgiEnv()

    grph = cgiEnv.GetGraph()
    cpu_property = lib_properties.MakeProp("cpu")
    rss_property = lib_properties.MakeProp("rss")
    vms_property = lib_properties.MakeProp("vms")

    property_process_perf = lib_properties.MakeProp("Processes performances")

    for proc in psutil.process_iter():
        node_process = lib_common.gUriGen.PidUri(proc.pid)

        sample_root_node = rdflib.BNode()
        grph.add((node_process, property_process_perf, sample_root_node))

        timestamp_node = lib_kbase.time_stamp_now_node()

        # TODO: pc.property_information is the default property for sorting.
        # TODO: This could use a specific timestamp property, for example "point in time" P585
        grph.add((sample_root_node, pc.property_information, timestamp_node))

        cpu_percent = proc.cpu_percent(interval=0)
        grph.add((sample_root_node, cpu_property, lib_util.NodeLiteral(cpu_percent)))

        try:
            memory_dict = proc.memory_full_info()
            grph.add((sample_root_node, rss_property, lib_util.NodeLiteral(memory_dict.rss)))
            grph.add((sample_root_node, vms_property, lib_util.NodeLiteral(memory_dict.vms)))
        except psutil.AccessDenied:
            pass

    cgiEnv.OutCgiRdf("LAYOUT_RECT", [property_process_perf])


def Main():
    if lib_util.is_snapshot_behaviour():
        Snapshot()
    else:
        while True:
            Snapshot()
            # TODO: This should be a parameter. How to modify it when the process is started ?
            # TODO: For deamons, the parameters could simply be written in a file each time they
            # TODO: are updated, then they would be read again: This is very fast and reliable.
            # TODO: Possibly store the parameters in the triple-store.
            time.sleep(20)


if __name__ == '__main__':
    Main()
