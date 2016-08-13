#!/usr/bin/python

"""
Processes tree
"""

import sys
import psutil
import rdflib
import lib_common
from sources_types import CIM_Process
from lib_properties import pc

def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = rdflib.Graph()

	# With a dictionary so node are created once only.
	# This attribute belongs to the function (defintion), and not to the function call.
	# Must be mindful of threading and recursion.

	Main.dictPidToNode = {}

	def PidToNode(pid):
		global dictPidToNode
		try:
			return Main.dictPidToNode[pid]
		except KeyError:
			node = lib_common.gUriGen.PidUri(pid)
			Main.dictPidToNode[pid] = node
			return node

	for proc in psutil.process_iter():
		if lib_common.UselessProc(proc):
			continue

		procName = proc.name

		pid = proc.pid
		parent_pid = CIM_Process.PsutilProcToPPid(proc)

		# Built the same way in other RDF documents.
		node_process = PidToNode(pid)
		parent_node_process = PidToNode(parent_pid)

		# We avoid duplicating the edges. Why would the RFD merge do?
		grph.add( ( node_process, pc.property_ppid, parent_node_process ) )
		grph.add( ( node_process, pc.property_pid, rdflib.Literal(pid) ) )

		# TODO: Add the username as a property ? Change the color with the username ?
		# procUsername = lib_common.PsutilProcToUser(proc)
		# grph.add( ( node_process, pc.property_user, rdflib.Literal(procUsername) ) )

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()
