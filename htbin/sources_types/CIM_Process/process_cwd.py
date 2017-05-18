#!/usr/bin/python

"""
Current working directory
"""

import sys
import psutil
import rdflib
import lib_common
from sources_types import CIM_Process
from lib_properties import pc

def Main():
	cgiEnv = lib_common.CgiEnv()
	try:
		top_pid = int( cgiEnv.GetId() )
	except Exception:
		lib_common.ErrorMessageHtml("Must provide a pid")

	grph = rdflib.Graph()

	proc_obj = CIM_Process.PsutilGetProcObj(top_pid)

	node_process = lib_common.gUriGen.PidUri(top_pid)
	CIM_Process.AddInfo( grph, node_process, [ str(top_pid) ] )

	proc_cwd,proc_msg = CIM_Process.PsutilProcCwd(proc_obj)

	if proc_cwd:
		node_cwd = lib_common.gUriGen.FileUri( proc_cwd )
		grph.add( ( node_process, pc.property_cwd, node_cwd ) )
	else:
		# The PID is added to the message such as "Access denied", so it is specific to the process
		# and prevents nodes with the same text to be merged in RDF or when displayed in Javascript.
		msgSpecific = "%s:Pid=%d" % (proc_msg,top_pid)
		grph.add( ( node_process, pc.property_information, rdflib.Literal(msgSpecific)) )

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()
