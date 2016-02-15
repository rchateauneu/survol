#!/usr/bin/python

import sys
import psutil
import rdflib
import lib_util
import lib_common
from lib_properties import pc

cgiEnv = lib_common.CgiEnv("System-wide open files")

grph = rdflib.Graph()

################################################################################
# Avoids storing files which are accessed by one process only.
def AddPidFileLink(grph,node_process,path):

	# TODO: Resolve symbolic links. Do not do that if shared memory.
	# TODO: AVOIDS THESE TESTS FOR SHARED MEMORY !!!!
	if lib_common.MeaningLessFile(path):
		return

	# This because we want to show only the files which are accessed by
	# several processes, otherwise this is too hungry.
	if path in AddPidFileLink.dictFiles:
		# This was: Literal( "//" + hostName + "/" + path )
		fileNode = lib_common.gUriGen.FileUri( path )

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

AddPidFileLink.dictFiles = {}

sys.stderr.write("open_files\n")
sys.stderr.flush()


################################################################################

# Maybe this is done in another CGI. What happens when merging ?
grph.add( ( lib_common.nodeMachine, pc.property_hostname, rdflib.Literal( lib_util.currentHostname ) ) )


reportSharedAccessOnly = False

# https://code.google.com/p/psutil/issues/detail?id=340
# This might hang.



for proc in psutil.process_iter():
	try:
		if lib_common.UselessProc(proc):
			continue


		# The process might have left in the meantime.
		pid = proc.pid

		node_process = None
		
		# Not sure about the access rights needed to investigate other processes...
		# BEWARE: On Windows this might be hanging for ever !
		# continue

		#cgiEnv.OutCgiRdf(grph)
		#sys.exit(0)



		# http://code.google.com/p/psutil/issues/detail?id=340
		# https://github.com/giampaolo/psutil/issues/340
		for fil in proc.get_open_files():
			continue
			# Adds the process node only if it has at least one open file.
			if node_process == None:
				node_process = lib_common.gUriGen.PidUri(pid)
				grph.add( ( node_process, pc.property_pid, rdflib.Literal(pid) ) )

			# TODO: What about files on a shared drive?
			if reportSharedAccessOnly:
				# This takes into account only files accessed by several processes.
				AddPidFileLink( grph, node_process, fil.path )
			else:
				fileNode = lib_common.gUriGen.FileUri( fil.path )
				grph.add( ( node_process, pc.property_open_file, fileNode ) )

	# Does not work with psutil:3.2.2
	#except psutil._error.AccessDenied:
		# Unfortunately, if the running process does not have enough privileges,
		# the script will go here very often.
		# We might avoid this with groups, maybe.
	#	pass
	except:
		pass

cgiEnv.OutCgiRdf(grph)

