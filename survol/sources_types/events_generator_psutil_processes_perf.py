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

#import lib_webserv
#import lib_tabular

Usable = lib_util.UsableLinux

IsEventsGenerator = True

################################################################################

# This runs in the HTTP server and uses the data from the queue.
# This reads a record from the queue and builds a RDF relation with it.
# def TopDeserialize( log_strm, grph, tpl):
#     pidstr = tpl[0]
#     node_process = lib_common.gUriGen.PidUri(pidstr)
# 
#     # TODO: Ajouter un time-stamp chaque triple.
#     # Plutot que deserialiser les triplets un par un,
#     # il faudrait tous les deserialiser dans un container a part,
#     # et a la fin seulement, batir un graphique etc...
# 
#     # Ou alors modifier le node en y ajoutant quelque chose a la fin ?
#     # Par exemple mettre a jour un graphique vers lequel pointerait le RDF ?
# 
#     # grph.add( ( node_process, pc.property_cpu, lib_common.NodeLiteral(tpl[1]) ) )
#     # grph.add( ( node_process, pc.property_virt, lib_common.NodeLiteral(tpl[2]) ) )
#     lib_tabular.AddData( log_strm, grph, node_process, "CIM_Process", pidstr, [ "cpu", "virt" ], tpl[ 1 : 3 ] )

################################################################################

# Runs in the subprocess of the HTTP server and parses the output of "tcpdump".
# The entity id should be the default value and is not relevant.
def Main():
    cgiEnv = lib_common.CgiEnv()

    grph = cgiEnv.GetGraph()
    cpu_property = lib_properties.MakeProp("cpu")
    rss_property = lib_properties.MakeProp("rss")
    vms_property = lib_properties.MakeProp("vms")

    for proc in psutil.process_iter():
        node_process = lib_common.gUriGen.PidUri(proc.pid)

        cpu_percent = proc.get_cpu_percent(interval=0)
        grph.add((node_process, cpu_property, lib_common.NodeLiteral(cpu_percent)))

        rss, vms = proc.get_memory_info()
        grph.add((node_process, rss_property, lib_common.NodeLiteral(rss)))
        grph.add((node_process, vms_property, lib_common.NodeLiteral(vms)))

    cgiEnv.OutCgiRdf()

################################################################################

if __name__ == '__main__':
    Main()
elif __name__ == '__daemon__':
    while True:
        Main()
        time.sleep(20)
