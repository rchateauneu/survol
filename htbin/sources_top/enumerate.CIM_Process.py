#!/usr/bin/python

import psutil
import rdflib
import lib_common
import lib_entities.lib_entity_CIM_Process as lib_entity_CIM_Process
from lib_properties import pc

cgiEnv = lib_common.CgiEnv("Processes tree")

grph = rdflib.Graph()

# With a dictionary so node are created once only.
dictPidToNode = {}

def PidToNode(pid):
	global dictPidToNode
	try:
		return dictPidToNode[pid]
	except KeyError:
		node = lib_common.gUriGen.PidUri(pid)
		dictPidToNode[pid] = node
		return node

for proc in psutil.process_iter():
	if lib_common.UselessProc(proc):
		continue

	procName = proc.name

	pid = proc.pid
	parent_pid = lib_entity_CIM_Process.PsutilProcToPPid(proc)

	# Built the same way in other RDF documents.
	node_process = PidToNode(pid)
	parent_node_process = PidToNode(parent_pid)

	# We avoid duplicating the edges. Why would the RFD merge do?
	grph.add( ( node_process, pc.property_ppid, parent_node_process ) )
	grph.add( ( node_process, pc.property_pid, rdflib.Literal(pid) ) )

	# TODO: Add the username as a property ? Change the color with the username ?
	# procUsername = lib_common.PsutilProcToUser(proc)
	# grph.add( ( node_process, pc.property_user, rdflib.Literal(procUsername) ) )

# With the "dot" layout, the image is too high.
# TODO: It would be nice to be able to change the layout.
cgiEnv.OutCgiRdf(grph)

