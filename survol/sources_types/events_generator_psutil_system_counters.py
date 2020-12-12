#!/usr/bin/env python

"""
Continuous information about the operating system.
"""

import os
import sys
import time
import psutil
import rdflib

import lib_kbase
import lib_util
import lib_common
from lib_properties import pc
import lib_properties


def _add_property_values(grph, root_node, results_set, property_names, property_prefix):
    for property_name in property_names:
        property_node = lib_properties.MakeProp("%s.%s" % (property_prefix, property_name))
        property_value = getattr(results_set, property_name)
        grph.add((root_node, property_node, lib_util.NodeLiteral(property_value)))


def _add_system_counters_to_sample_node(grph, sample_node):
    # sswap(total=2097147904L, used=886620160L, free=1210527744L, percent=42.3, sin=1050411008, sout=1906720768)
    _add_property_values(
        grph,
        sample_node,
        psutil.swap_memory(),
        ["total", "used", "free", "percent", "sin", "sout"],
        "swap_memory")

    # svmem(total=10367352832, available=6472179712, percent=37.6, used=8186245120, free=2181107712,
    # active=4748992512, inactive=2758115328, buffers=790724608, cached=3500347392, shared=787554304, slab=199348224)
    _add_property_values(
        grph,
        sample_node,
        psutil.virtual_memory(),
        ["total", "available", "percent", "used", "free"],
        "virtual_memory")

    # sdiskio(read_count=8141, write_count=2431, read_bytes=290203,
    # write_bytes=537676, read_time=5868, write_time=94922)
    _add_property_values(
        grph,
        sample_node,
        psutil.disk_io_counters(),
        ["read_count", "write_count", "read_bytes", "write_bytes", "read_time", "write_time"],
        "disk_io_counters")

    # snetio(bytes_sent=14508483, bytes_recv=62749361, packets_sent=84311,
    # packets_recv=94888, errin=0, errout=0, dropin=0, dropout=0)
    _add_property_values(
        grph,
        sample_node,
        psutil.net_io_counters(),
        ["bytes_sent", "bytes_recv", "packets_sent", "packets_recv", "errin", "errout", "dropin", "dropout"],
        "net_io_counters")


def Snapshot():
    cgiEnv = lib_common.CgiEnv()

    grph = cgiEnv.GetGraph()

    sample_root_node = rdflib.BNode()

    _add_system_counters_to_sample_node(grph, sample_root_node)

    property_system_counters = lib_properties.MakeProp("system_counters")

    current_node_hostname = lib_common.gUriGen.HostnameUri(lib_util.currentHostname)

    # TODO: pc.property_information is the default property for sorting.
    # TODO: This could use a specific timestamp property, for example "point in time" P585
    timestamp_node = lib_kbase.time_stamp_now_node()
    grph.add((sample_root_node, pc.property_information, timestamp_node))
    grph.add((current_node_hostname, property_system_counters, sample_root_node))

    cgiEnv.OutCgiRdf("LAYOUT_RECT", [property_system_counters])


def Main():
    if lib_util.is_snapshot_behaviour():
        Snapshot()
    else:
        while True:
            Snapshot()
            time.sleep(5)


if __name__ == '__main__':
    Main()
