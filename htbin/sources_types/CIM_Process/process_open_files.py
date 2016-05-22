#!/usr/bin/python

"""
Files opened by process
"""

import sys
import rdflib
import lib_common
import lib_entities.lib_entity_CIM_Process as lib_entity_CIM_Process

from lib_properties import pc

def Main():
	cgiEnv = lib_common.CgiEnv()
	top_pid = int( cgiEnv.GetId() )

	grph = rdflib.Graph()

	proc_obj = lib_entity_CIM_Process.PsutilGetProcObj(top_pid)

	# sys.stderr.write("top_pid=%d\n" % top_pid)

	node_process = lib_common.gUriGen.PidUri(top_pid)
	lib_entity_CIM_Process.AddInfo( grph, node_process, [ str(top_pid) ] )

	################################################################################

	try:
		fillist = lib_entity_CIM_Process.PsutilProcOpenFiles( proc_obj )
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Caught:"+str(exc)+":"+str(proc_obj))

	for fil in fillist:
		# TODO: Resolve symbolic links. Do not do that if shared memory.
		# TODO: AVOIDS THESE TESTS FOR SHARED MEMORY !!!!
		if lib_common.MeaninglessFile(fil.path,True,True):
			continue

		fileNode = lib_common.gUriGen.FileUri( fil.path )
		grph.add( ( node_process, pc.property_open_file, fileNode ) )

	# This works but not really necessary because there are not so many files.
	# cgiEnv.OutCgiRdf(grph, "", [pc.property_open_file] )
	cgiEnv.OutCgiRdf(grph,"LAYOUT_SPLINE")

if __name__ == '__main__':
	Main()
