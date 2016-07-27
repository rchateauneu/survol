#!/usr/bin/python

"""
Process shared memory segments
"""

import sys
import rdflib
import lib_common
from lib_properties import pc
import lib_entities.lib_entity_CIM_Process as lib_entity_CIM_Process

def Main():
	cgiEnv = lib_common.CgiEnv()
	pid = int( cgiEnv.GetId() )

	grph = rdflib.Graph()

	proc_obj = lib_entity_CIM_Process.PsutilGetProcObj(pid)

	nodeProcess = lib_common.gUriGen.PidUri(pid)

	try:
		all_maps = lib_entity_CIM_Process.PsutilProcMemmaps(proc_obj)
	except:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("get_memory_maps Pid=%d. Caught %s\n" % (pid,str(exc)) )

	for map in all_maps:
		# This, because all Windows paths are "standardized" by us.
		cleanMapPath = map.path.replace("\\","/")
		# sys.stderr.write("MapPath=%s cleanMapPath=%s memmapName=%s\n" % (map.path,cleanMapPath,memmapName))

		uriMemMap = lib_common.gUriGen.MemMapUri( cleanMapPath )

		grph.add( ( nodeProcess, pc.property_memmap, uriMemMap ) )


	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()

