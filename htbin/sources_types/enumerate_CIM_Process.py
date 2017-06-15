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

	grph = cgiEnv.GetGraph()

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

	# Problem here: There is a second loopkup to get the name of the process.
	# In the mean time, the process might have disappeared.
	# Another problem due to Windows is that a parent process might have exit,
	# although it children processes are not reassigned (As it is the case on Unix).
	# This is a "non-existent process".
	for proc in psutil.process_iter():
		if lib_common.UselessProc(proc):
			continue

		# proc=['__class__', '__delattr__', '__dict__', '__doc__', '__eq__', '__format__', '__getattribute__', '__hash__', '__init__', '__modu
		# le__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '
		# __weakref__', '_create_time', '_exe', '_gone', '_hash', '_ident', '_init', '_last_proc_cpu_times', '_last_sys_cpu_times', '_name', '
		# _pid', '_ppid', '_proc', 'as_dict', 'children', 'cmdline', 'connections', 'cpu_affinity', 'cpu_percent', 'cpu_times', 'create_time',
		#  'cwd', 'exe', 'io_counters', 'ionice', 'is_running', 'kill', 'memory_info', 'memory_info_ex', 'memory_maps', 'memory_percent', 'nam
		# e', 'nice', 'num_ctx_switches', 'num_handles', 'num_threads', 'open_files', 'parent', 'pid', 'ppid', 'resume', 'send_signal', 'statu
		# s', 'suspend', 'terminate', 'threads', 'username', 'wait']'
		# sys.stderr.write("proc=%s\n"%str(dir(proc)))

		procName = proc.name

		pid = proc.pid
		parent_pid = CIM_Process.PsutilProcToPPid(proc)

		# Built the same way in other RDF documents.
		node_process = PidToNode(pid)
		parent_node_process = PidToNode(parent_pid)

		# We avoid duplicating the edges. Why would the RDF merge do?
		grph.add( ( node_process, pc.property_ppid, parent_node_process ) )
		grph.add( ( node_process, pc.property_pid, rdflib.Literal(pid) ) )
		usrNam = CIM_Process.PsutilProcToUser(proc,None)
		if usrNam:
			grph.add( ( node_process, pc.property_user, rdflib.Literal(usrNam) ) )

		# TODO: Add the username as a property ? Change the color with the username ?
		# Pour les couleurs, on pourrait imaginer d'aller chercher les icones des utilisateurs
		# ou des programmes et d'en prendre la couleur dominante ?
		# Ou bien, si un objet est associe a un de nos packages, en prendre les attributs graphiques:
		# Si c'est un process oracle, on prend les couleurs de notre package Oracle etc...

		# procUsername = lib_common.PsutilProcToUser(proc)
		# grph.add( ( node_process, pc.property_user, rdflib.Literal(procUsername) ) )

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
