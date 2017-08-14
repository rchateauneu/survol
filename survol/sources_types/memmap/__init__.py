"""
Shareable memory segment
"""

import os
import sys
import lib_util
import lib_common
import psutil

from lib_properties import pc
from sources_types import CIM_Process

def EntityOntology():
	return ( ["Id"],)

# This returns a nice name given the parameter of the object.
# Same logic as CIM_DataFile.
# TODO: How to display the full path ?
def EntityName(entity_ids_arr,entity_host):
	entity_id = entity_ids_arr[0]
	# A file name can be very long, so it is truncated.
	file_basename = os.path.basename(entity_id)
	if file_basename == "":
		return entity_id
	else:
		return file_basename

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
	grph.add( ( lib_common.nodeMachine, pc.property_hostname, lib_common.NodeLiteral( lib_util.currentHostname ) ) )

	# This is also a file mapped into memory.
	uriMappedFile = lib_common.gUriGen.FileUri( fileName )

	uriMemMap = None

	try:
		statinfo = os.stat(fileName)
	except Exception:
		exc = sys.exc_info()[1]
		grph.add( ( uriMappedFile, lib_common.MakeProp("Error"), lib_common.NodeLiteral(str(exc)) ) )
		return

	fileSize = lib_util.AddSIUnit(statinfo.st_size, "B")
	grph.add( ( uriMappedFile, pc.property_file_size, lib_common.NodeLiteral(fileSize) ) )

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
			# sys.stderr.write("get_memory_maps Pid=%d. Caught %s\n" % (pid,str(exc)) )
			continue

		# sys.stderr.write("get_memory_maps OK Pid=%d:%s.\n" % (pid,str(all_maps)) )

		for map in all_maps:
			# This, because all Windows paths are "standardized" by us.
			cleanMapPath = map.path.replace("\\","/")

			# MapPath=C:\Windows\System32\KernelBase.dll fileName=c:\windows\system32\API-MS-WIN-CORE-LOCALIZATION-L1-1-0.DLL
			# sys.stderr.write("Pid=%d MapPath=%s cleanMapPath=%s fileName=%s\n" % (pid,map.path,cleanMapPath,fileName))

			if lib_util.isPlatformWindows:
				# Horrible conversion due to Windows ...
				sameFil = map.path.replace("\\","/").lower() == fileName.replace("\\","/").lower()
			else:
				sameFil = map.path == fileName

			if sameFil:
				sys.stderr.write("Pid=%d MapPath=%s cleanMapPath=%s fileName=%s\n" % (pid,map.path,cleanMapPath,fileName))
				# Maybe this is the first mapping we have found.
				if uriMemMap == None:
					uriMemMap = lib_common.gUriGen.MemMapUri( fileName )
					grph.add( ( uriMappedFile, pc.property_mapped, uriMemMap ) )
				nodeProcess = lib_common.gUriGen.PidUri(pid)
				# The property is reversed because of display.
				grph.add( ( uriMemMap, pc.property_memmap, nodeProcess ) )
				grph.add( ( nodeProcess, pc.property_pid, lib_common.NodeLiteral(pid) ) )

				# Displays the RSS only if different from the file size.
				if map.rss != statinfo.st_size:
					grph.add( ( nodeProcess, propMemoryRSS, lib_common.NodeLiteral(map.rss) ) )


