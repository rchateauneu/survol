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
import lib_util
import lib_common
from lib_properties import pc
import lib_properties


def Main():
    cgiEnv = lib_common.CgiEnv()

    grph = cgiEnv.GetGraph()
    cpu_property = lib_properties.MakeProp("cpu")
    rss_property = lib_properties.MakeProp("rss")
    vms_property = lib_properties.MakeProp("vms")

    for proc in psutil.process_iter():
        node_process = lib_common.gUriGen.PidUri(proc.pid)

        cpu_percent = proc.cpu_percent(interval=0)
        grph.add((node_process, cpu_property, lib_common.NodeLiteral(cpu_percent)))

        try:
            memory_dict = proc.memory_full_info()
            grph.add((node_process, rss_property, lib_common.NodeLiteral(memory_dict.rss)))
            grph.add((node_process, vms_property, lib_common.NodeLiteral(memory_dict.vms)))
        except psutil.AccessDenied:
            pass

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    if lib_util.is_snapshot_behaviour():
        Main()
    else:
        while True:
            Main()
            time.sleep(10)
