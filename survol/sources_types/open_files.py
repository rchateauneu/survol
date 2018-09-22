#!/usr/bin/python

"""
System-wide open files
"""

import sys
import lib_util
import lib_common
from sources_types import CIM_Process
from lib_properties import pc

def PathToNod(path):
	try:
		return Main.dictPathToNod[path]
	except KeyError:
		filNod = lib_common.gUriGen.FileUri( path )
		Main.dictPathToNod[path] = filNod
		return filNod

# Avoids storing files which are accessed by one process only.
def AddPidFileLink(grph,node_process,path):

	# TODO: Resolve symbolic links. Do not do that if shared memory.
	# TODO: AVOIDS THESE TESTS FOR SHARED MEMORY !!!!

	# This because we want to show only the files which are accessed by
	# several processes, otherwise this is too hungry.
	if path in AddPidFileLink.dictFiles:
		fileNode = PathToNod( path )

		# Creates also a node for the first process.
		previousProcessNode = AddPidFileLink.dictFiles[path]
		if previousProcessNode != "Done":
			grph.add( ( previousProcessNode, pc.property_open_file, fileNode ) )
			# Can use the path as a key as it runs on the current node only.
			AddPidFileLink.dictFiles[path] = "Done"
		grph.add( ( node_process, pc.property_open_file, fileNode ) )
	else:
		# Just store the node. Will see later if accessed by more than two process.
		AddPidFileLink.dictFiles[path] = node_process

def Main():
	paramkeyShowSharedLib = "Show shared libraries"
	paramkeyShowFontFiles = "Show font files"
	paramkeyShowNonShared = "Show non shared files"

	# TODO: At the moment, only uses false default values for boolean parameters,
	# TODO: because CGI and the CGI lib do not send empty strings.
	cgiEnv = lib_common.CgiEnv(
		parameters = { paramkeyShowSharedLib : False,
					   paramkeyShowFontFiles : False,
					   paramkeyShowNonShared : False }
	)

	flagShowSharedLib = bool(cgiEnv.GetParameters( paramkeyShowSharedLib ))
	flagShowFontFiles = bool(cgiEnv.GetParameters( paramkeyShowFontFiles ))
	flagShowNonShared = bool(cgiEnv.GetParameters( paramkeyShowNonShared ))

	grph = cgiEnv.GetGraph()

	################################################################################

	Main.dictPathToNod = {}

	AddPidFileLink.dictFiles = {}

	# Maybe this is done in another CGI. What happens when merging ?
	grph.add( ( lib_common.nodeMachine, pc.property_hostname, lib_common.NodeLiteral( lib_util.currentHostname ) ) )

	# https://code.google.com/p/psutil/issues/detail?id=340
	# This might hang.

	for proc in CIM_Process.ProcessIter():
		try:
			if lib_common.UselessProc(proc):
				continue

			pid = proc.pid

			node_process = None

			# http://code.google.com/p/psutil/issues/detail?id=340
			# https://github.com/giampaolo/psutil/issues/340
			for fil in CIM_Process.PsutilProcOpenFiles( proc ):

				# Some files are not interesting even if accessed by many processes.
				if lib_common.MeaninglessFile(fil.path, not flagShowSharedLib, not flagShowFontFiles ):
					continue

				# Adds the process node only if it has at least one open file.
				if node_process == None:
					node_process = lib_common.gUriGen.PidUri(pid)
					grph.add( ( node_process, pc.property_pid, lib_common.NodeLiteral(pid) ) )

				# TODO: What about files on a shared drive?
				if flagShowNonShared:
					fileNode = PathToNod( fil.path )
					grph.add( ( node_process, pc.property_open_file, fileNode ) )
				else:
					# This takes into account only files accessed by several processes.
					AddPidFileLink( grph, node_process, fil.path )

		# except psutil.AccessDenied:
		#	pass
		except:
			exc = sys.exc_info()[1]
			WARNING("Exception:%s", str(exc))
			pass

	cgiEnv.OutCgiRdf("LAYOUT_SPLINE")
	# cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()


