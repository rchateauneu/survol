"""
Shareable memory segment
"""

import os
import sys
import lib_util
import lib_common
import psutil
import rdflib

from lib_properties import pc
from sources_types import CIM_Process


# A map file is associated to a file.
def AddInfo(grph,node,entity_ids_arr):
	nameMappedFile = entity_ids_arr[0]
	# sys.stderr.write("AddInfo entity_id=%s\n" % pidProc )
	exec_node = lib_common.gUriGen.FileUri( nameMappedFile )
	grph.add( ( node, lib_common.MakeProp("Mapped file"), exec_node ) )

# This displays all processes mapping a given filename.
# This simply iterates on processes, then on mapped files of each process.
# This is not very efficient but there is no other way.
def DisplayMappedProcesses(grph,fileName):
	grph.add( ( lib_common.nodeMachine, pc.property_hostname, rdflib.Literal( lib_util.currentHostname ) ) )

	# This is also a file mapped into memory.
	uriMappedFile = lib_common.gUriGen.FileUri( fileName )

	uriMemMap = None

	try:
		statinfo = os.stat(fileName)
	except Exception:
		exc = sys.exc_info()[1]
		grph.add( ( uriMappedFile, lib_common.MakeProp("Error"), rdflib.Literal(str(exc)) ) )
		return


	fileSize = statinfo.st_size
	grph.add( ( uriMappedFile, lib_common.MakeProp("File size"), rdflib.Literal(fileSize) ) )

	propMemoryRSS = lib_common.MakeProp("Resident Set Size")
	for proc in psutil.process_iter():

		if lib_common.UselessProc(proc):
			continue

		pid = proc.pid

		try:
			all_maps = CIM_Process.PsutilProcMemmaps(proc)
		except:
			# Probably psutil.AccessDenied
			exc = sys.exc_info()[1]
			sys.stderr.write("get_memory_maps Pid=%d. Caught %s\n" % (pid,str(exc)) )
			continue

		for map in all_maps:
			# This, because all Windows paths are "standardized" by us.
			cleanMapPath = map.path.replace("\\","/")
			# sys.stderr.write("MapPath=%s cleanMapPath=%s memmapName=%s\n" % (map.path,cleanMapPath,memmapName))

			if cleanMapPath == fileName:
				# Maybe this is the first mapping we have found.
				if uriMemMap == None:
					uriMemMap = lib_common.gUriGen.MemMapUri( fileName )
					grph.add( ( uriMappedFile, pc.property_mapped, uriMemMap ) )
				nodeProcess = lib_common.gUriGen.PidUri(pid)
				grph.add( ( nodeProcess, pc.property_memmap, uriMemMap ) )
				grph.add( ( nodeProcess, pc.property_pid, rdflib.Literal(pid) ) )

				# Displays the RSS only if different from the file size.
				if map.rss != fileSize:
					grph.add( ( nodeProcess, propMemoryRSS, rdflib.Literal(map.rss) ) )


