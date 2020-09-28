#!/usr/bin/env python

"""
Continuous information about the operating system.
"""

import os
import re
import sys
import time
import psutil
import lib_util
import lib_common
from lib_properties import pc
import lib_properties


def Main():
    cgiEnv = lib_common.CgiEnv()

    grph = cgiEnv.GetGraph()

    # TODO: The values are arbitrarily added to the node of the host, but a time-stamp should be somewhere.
    current_node_hostname = lib_common.gUriGen.HostnameUri(lib_util.currentHostname)

    def add_property_values(results_set, property_names, property_prefix):
        for property_name in property_names:
            property_node = lib_properties.MakeProp("%s.%s" % (property_prefix, property_name))
            property_value = getattr(results_set, property_name)
            grph.add((current_node_hostname, property_node, lib_common.NodeLiteral(property_value)))

    # sswap(total=2097147904L, used=886620160L, free=1210527744L, percent=42.3, sin=1050411008, sout=1906720768)
    add_property_values(psutil.swap_memory(),
                        ["total", "used", "free", "percent", "sin", "sout"],
                        "swap_memory")

    # svmem(total=10367352832, available=6472179712, percent=37.6, used=8186245120, free=2181107712,
    # active=4748992512, inactive=2758115328, buffers=790724608, cached=3500347392, shared=787554304, slab=199348224)
    add_property_values(
        psutil.virtual_memory(),
        ["total", "available", "percent", "used", "free"],
        "virtual_memory")

    # sdiskio(read_count=8141, write_count=2431, read_bytes=290203,
    # write_bytes=537676, read_time=5868, write_time=94922)
    add_property_values(
        psutil.disk_io_counters(),
        ["read_count", "write_count", "read_bytes", "write_bytes", "read_time", "write_time"],
        "disk_io_counters")

    # snetio(bytes_sent=14508483, bytes_recv=62749361, packets_sent=84311,
    # packets_recv=94888, errin=0, errout=0, dropin=0, dropout=0)
    add_property_values(
        psutil.net_io_counters(),
        ["bytes_sent", "bytes_recv", "packets_sent", "packets_recv", "errin", "errout", "dropin", "dropout"],
        "net_io_counters")

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    if lib_util.is_snapshot_behaviour():
        sys.stderr.write(__file__ + " starting in snapshot mode.")
        Main()
    else:
        sys.stderr.write(__file__ + " starting in events mode.")
        while True:
            Main()
            time.sleep(20)
