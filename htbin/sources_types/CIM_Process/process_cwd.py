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

	try:
		proc_cwd = proc_obj.getcwd()
		proc_msg = None
	except CIM_Process.AccessDenied:
		proc_cwd = None
		proc_msg = "Process %d: Cannot get current working directory: %s" % (top_pid,str(sys.exc_info()))
	except AttributeError:
		proc_cwd = proc_obj.cwd()
		proc_msg = None

	if proc_cwd:
		node_cwd = lib_common.gUriGen.FileUri( proc_cwd )
		grph.add( ( node_process, pc.property_cwd, node_cwd ) )
	else:
		grph.add( ( node_process, pc.property_information, rdflib.Literal(proc_msg)) )

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()
