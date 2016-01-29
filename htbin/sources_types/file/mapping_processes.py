#!/usr/bin/python

import re
import sys
import psutil
import rdflib

import lib_common
from lib_properties import pc

cgiEnv = lib_common.CgiEnv("Processes mapping a file into memory")
fileName = cgiEnv.GetId()

grph = rdflib.Graph()

grph.add( ( lib_common.nodeMachine, pc.property_hostname, rdflib.Literal( lib_common.hostName ) ) )


# This is also a file mapped into memory.
uriMappedFile = lib_common.gUriGen.FileUri( fileName )

uriMemMap = None

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

		if map.path == fileName:
			# Maybe this is the first mapping we have found.
			if uriMemMap == None:
				uriMemMap = lib_common.gUriGen.MemMapUri( fileName )
				grph.add( ( uriMappedFile, pc.property_mapped, uriMemMap ) )
			nodeProcess = lib_common.gUriGen.PidUri(pid)
			grph.add( ( nodeProcess, pc.property_memmap, uriMemMap ) )
			grph.add( ( nodeProcess, pc.property_pid, rdflib.Literal(pid) ) )



cgiEnv.OutCgiRdf(grph)

