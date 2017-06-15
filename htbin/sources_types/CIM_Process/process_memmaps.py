#!/usr/bin/python

"""
Shared memory segments
"""

import sys
import rdflib
import lib_common
from lib_properties import pc
from sources_types import CIM_Process

def Main():
	cgiEnv = lib_common.CgiEnv()
	pid = int( cgiEnv.GetId() )

	grph = cgiEnv.GetGraph()

	proc_obj = CIM_Process.PsutilGetProcObj(pid)

	nodeProcess = lib_common.gUriGen.PidUri(pid)

	try:
		all_maps = CIM_Process.PsutilProcMemmaps(proc_obj)
	except:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("get_memory_maps Pid=%d. Caught %s\n" % (pid,str(exc)) )

	propMemoryRSS = lib_common.MakeProp("Resident Set Size")
	for map in all_maps:
		# This, because all Windows paths are "standardized" by us.
		cleanMapPath = map.path.replace("\\","/")

		uriMemMap = lib_common.gUriGen.MemMapUri( cleanMapPath )

		grph.add( ( uriMemMap, propMemoryRSS, rdflib.Literal(map.rss) ) )
		grph.add( ( nodeProcess, pc.property_memmap, uriMemMap ) )

	cgiEnv.OutCgiRdf(grph, "LAYOUT_SPLINE")

if __name__ == '__main__':
	Main()

