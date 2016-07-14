#!/usr/bin/python

"""
Memory map connected processes
"""

import re
import sys
import psutil
import rdflib
import lib_util
import lib_common
from lib_properties import pc
import lib_entities.lib_entity_CIM_Process as lib_entity_CIM_Process

def Main():
	cgiEnv = lib_common.CgiEnv()
	memmapName = cgiEnv.GetId()

	grph = rdflib.Graph()

	grph.add( ( lib_common.nodeMachine, pc.property_hostname, rdflib.Literal( lib_util.currentHostname ) ) )

	uriMemMap = lib_common.gUriGen.MemMapUri( memmapName )

	# This is also a file mapped into memory.
	uriMappedFile = lib_common.gUriGen.FileUri( memmapName )

	grph.add( ( uriMappedFile, pc.property_mapped, uriMemMap ) )

	procList = []

	for proc in psutil.process_iter():

		pid = proc.pid

		if lib_common.UselessProc(proc):
			continue

		# sys.stderr.write("Pid=%d\n" % pid )

		try:
			all_maps = lib_entity_CIM_Process.PsutilProcMemmaps(proc)
		except:
			exc = sys.exc_info()[1]
			sys.stderr.write("get_memory_maps Pid=%d. Caught %s\n" % (pid,str(exc)) )
			continue

		# sys.stderr.write("NbMaps=%d\n" % len(all_maps) )

		for map in all_maps:
			# This, because all Windows paths are "standardized" by us.
			cleanMapPath = map.path.replace("\\","/")
			# sys.stderr.write("MapPath=%s cleanMapPath=%s memmapName=%s\n" % (map.path,cleanMapPath,memmapName))

			if cleanMapPath == memmapName:
				nodeProcess = lib_common.gUriGen.PidUri(pid)
				grph.add( ( nodeProcess, pc.property_memmap, uriMemMap ) )
				grph.add( ( nodeProcess, pc.property_pid, rdflib.Literal(pid) ) )

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()
