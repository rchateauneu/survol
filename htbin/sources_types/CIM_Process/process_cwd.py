#!/usr/bin/python

# One node containing the current directory of the process.

#!/usr/bin/python

import sys
import psutil
import rdflib
import lib_common
import lib_entities.lib_entity_CIM_Process as lib_entity_CIM_Process
from lib_properties import pc

def Main():
	cgiEnv = lib_common.CgiEnv("Current working directory")
	try:
		top_pid = int( cgiEnv.GetId() )
	except Exception:
		lib_common.ErrorMessageHtml("Must provide a pid")

	grph = rdflib.Graph()

	proc_obj = lib_entity_CIM_Process.PsutilGetProcObj(top_pid)

	try:
		proc_cwd = proc_obj.getcwd()
	except lib_entity_CIM_Process.AccessDenied:
		lib_common.ErrorMessageHtml("Cannot get current directory: Access denied")
	except AttributeError:
		proc_cwd = "Cannot get cwd"

	node_process = lib_common.gUriGen.PidUri(top_pid)
	lib_entity_CIM_Process.AddInfo( grph, node_process, [ str(top_pid) ] )

	node_cwd = lib_common.gUriGen.FileUri( proc_cwd )
	grph.add( ( node_process, pc.property_cwd, node_cwd ) )

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()
