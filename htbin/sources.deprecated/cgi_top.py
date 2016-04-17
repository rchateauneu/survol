#!/usr/bin/python

# This scripts displays information about running processes: CPU, memory etc...
# into a RDF document. It can be processed through the
# RDF "integrator" which should calculate averages and extremums of the CPU and memory loads.

import lib_common

import os
import re
import sys
import time
import rdflib
import psutil
from rdflib import Literal
from lib_common import pc

import lib_webserv

################################################################################

# This runs in the HTTP server and uses the data from the queue.
# This reads a record from the queue and builds a RDF relation with it.
def TopDeserialize(grph, tuple):
	node_process = lib_common.PidUri(tuple[0])
	grph.add( ( node_process, pc.property_cpu, Literal(tuple[1]) ) )
	grph.add( ( node_process, pc.property_virt, Literal(tuple[2]) ) )

################################################################################

# Runs in the subprocess of the HTTP server and parses the output of "tcpdump".
# The entity id should be the default value and is not relevant.
def TopEngine(sharedTupleQueue,entityId):
	while 1:
		# Should be a parameter.
		time.sleep(1)
		for proc in psutil.process_iter():
			pid = proc.pid
			cpu_percent = proc.get_cpu_percent(interval=0)
			rss, vms = proc.get_memory_info()
			sharedTupleQueue.put( ( pid, cpu_percent, vms ) )

################################################################################

# Conventional port number for TCP dump RDF generation.
TopPort = 23456

# This is the CGI script started by Apache.
if __name__ == '__main__':
	lib_webserv.DoTheJob(TopEngine,TopPort,TopDeserialize,__file__)

