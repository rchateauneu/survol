#!/usr/bin/env python

"""
Disk usage
"""

import os
import sys
import time
import psutil
import lib_util
import lib_common
from lib_properties import pc


def Main():
    cgiEnv = lib_common.ScriptEnvironment()
    partition_nam = cgiEnv.GetId()

    partition_node = lib_common.gUriGen.DiskPartitionUri(partition_nam)

    grph = cgiEnv.GetGraph()

    dsk_usage = psutil.disk_usage(partition_nam)

    grph.add((partition_node, pc.property_disk_used, lib_util.NodeLiteral(dsk_usage.used)))
    grph.add((partition_node, pc.property_disk_free, lib_util.NodeLiteral(dsk_usage.free)))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
