#!/usr/bin/python

import lib_common

import os
import cgi
import psutil
import rdflib
from lib_common import pc

grph = rdflib.Graph()

def tree_subprocesses(proc_obj):    
	if lib_common.UselessProc(proc_obj):
		return

	node_process = lib_common.PidUri(proc_obj.pid)

	for child in proc_obj.get_children(recursive=False):
		node_child = lib_common.PidUri(child.pid)
		grph.add( ( node_process, pc.property_ppid, node_child ) )
		tree_subprocesses(child)

# Recursively add links for the parent processes.
def tree_parent_process(proc_obj):    
	if proc_obj.pid == 0 or proc_obj.pid == 1:
		return
	if lib_common.UselessProc(proc_obj):
		return

	node_process = lib_common.PidUri(proc_obj.pid)
	node_pprocess = lib_common.PidUri(proc_obj.ppid)
	grph.add( ( node_pprocess, pc.property_ppid, node_process ) )
	parent_proc_obj = psutil.Process(proc_obj.ppid)
	tree_parent_process( parent_proc_obj )


arguments = cgi.FieldStorage()
root_pid = int( arguments["entity_id"].value )

proc_obj = psutil.Process(root_pid)

# Sub-processes, recursion.
tree_subprocesses( proc_obj )

# Now display the parent processes.
# It could be done in a loop instead of recursive calls.
tree_parent_process( proc_obj )

lib_common.OutCgiRdf(grph)

