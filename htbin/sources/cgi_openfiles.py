#!/usr/bin/python

import sys
import psutil
import rdflib

import lib_common
from lib_common import pc
from rdflib import URIRef, BNode, Literal

grph = rdflib.Graph()

################################################################################
# Avoids storing files which are accessed by one process only.
def AddPidFileLink(grph,processNode,path):

	# TODO: Resolve symbolic links. Do not do that if shared memory.
	# TODO: AVOIDS THESE TESTS FOR SHARED MEMORY !!!!
	if lib_common.MeaningLessFile(path):
		return

	# This because we want to show only the files which are accessed by
	# several processes, otherwise this is too hungry.
	if path in AddPidFileLink.dictFiles:
		# This was: Literal( "//" + hostName + "/" + path )
		fileNode = lib_common.FileUri( path )

		# Creates also a node for the first process.
		previousProcessNode = AddPidFileLink.dictFiles[path]
		if previousProcessNode != "Done":
			grph.add( ( previousProcessNode, pc.property_open_file, fileNode ) )
			# Can use the path as a key as it runs on the current node only.
			AddPidFileLink.dictFiles[path] = "Done"
		grph.add( ( processNode, pc.property_open_file, fileNode ) )
	else:
		# Just store the node. Will see later if accessed by more than two process.
		AddPidFileLink.dictFiles[path] = processNode

AddPidFileLink.dictFiles = {}

################################################################################

# Maybe this is done in another CGI. What happens when merging ?
grph.add( ( lib_common.nodeMachine, pc.property_hostname, Literal( lib_common.hostName ) ) )

for proc in psutil.process_iter():
	try:
		if lib_common.UselessProc(proc):
			continue

		# The process might have left in the meantime.
		pid = proc.pid

		node_process = lib_common.PidUri(pid)

		# Not sure about the access rights needed to investigat other processes...
		for fil in proc.get_open_files():
			# This takes into account only files accessed by several processes.
			# TODO: What about files on a shared drive?
			AddPidFileLink( grph, node_process, fil.path )

	except psutil._error.AccessDenied:
		# Unfortunately, if the running process does not have enough privileges,
		# the script will go here very often.
		# We might avoid this with groups, maybe.
		pass
	except:
		pass

lib_common.OutCgiRdf(grph)

