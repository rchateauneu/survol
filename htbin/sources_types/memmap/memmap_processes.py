#!/usr/bin/python

import re
import sys
import psutil
import rdflib
import lib_util
import lib_common
from lib_properties import pc

cgiEnv = lib_common.CgiEnv("Processes connected to a memory map")
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

	sys.stderr.write("Pid=%d\n" % pid )

	try:
		all_maps = proc.get_memory_maps()
	except:
		sys.stderr.write("Caught exception in get_memory_maps Pid=%d\n" % pid )
		continue

	sys.stderr.write("NbMaps=%d\n" % len(all_maps) )

	for map in all_maps:
		sys.stderr.write("MapPath=%s\n" % map.path)

		if map.path == memmapName:
			nodeProcess = lib_common.gUriGen.PidUri(pid)
			grph.add( ( nodeProcess, pc.property_memmap, uriMemMap ) )
			grph.add( ( nodeProcess, pc.property_pid, rdflib.Literal(pid) ) )

cgiEnv.OutCgiRdf(grph)

