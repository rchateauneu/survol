#!/usr/bin/python

"""
This scripts displays information about running processes: CPU, memory etc...
into a RDF document. It can be processed through the
RDF "integrator" which should calculate averages and extremums of the CPU and memory loads.
"""

import lib_common

import os
import re
import sys
import time
import rdflib
import psutil
from lib_properties import pc

import lib_webserv
import lib_tabular

################################################################################

# This runs in the HTTP server and uses the data from the queue.
# This reads a record from the queue and builds a RDF relation with it.
def TopDeserialize( log_strm, grph, tpl):
	pidstr = tpl[0]
	node_process = lib_common.gUriGen.PidUri(pidstr)

	# TODO: Ajouter un time-stamp chaque triple.
	# Plutot que deserialiser les triplets un par un,
	# il faudrait tous les deserialiser dans un container a part,
	# et a la fin seulement, batir un graphique etc...

	# Ou alors modifier le node en y ajoutant quelque chose a la fin ?
	# Par exemple mettre a jour un graphique vers lequel pointerait le RDF ?

	# grph.add( ( node_process, pc.property_cpu, rdflib.Literal(tpl[1]) ) )
	# grph.add( ( node_process, pc.property_virt, rdflib.Literal(tpl[2]) ) )
	lib_tabular.AddData( log_strm, grph, node_process, "CIM_Process", pidstr, [ "cpu", "virt" ], tpl[ 1 : 3 ] )

################################################################################

# Runs in the subprocess of the HTTP server and parses the output of "tcpdump".
# The entity id should be the default value and is not relevant.
def TopEngine(sharedTupleQueue,entityId):
	while 1:
		# Should be a parameter.
		sys.stderr.write("Top pid=%d entity=%s sz=%d" % ( os.getpid(), entityId, sharedTupleQueue.qsize() ) )
		for proc in psutil.process_iter():
			pid = proc.pid
			cpu_percent = proc.get_cpu_percent(interval=0)
			rss, vms = proc.get_memory_info()
			sharedTupleQueue.put( ( pid, cpu_percent, vms ) )
		time.sleep(20)
	# Should never happen.
	return "top execution end"

################################################################################

# This is the CGI script started by Apache.
if __name__ == '__main__':
	lib_webserv.DoTheJob(TopEngine,TopDeserialize,__file__,"top processes statistics")

