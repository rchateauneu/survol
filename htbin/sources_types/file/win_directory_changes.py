#!/usr/bin/python

import os
import subprocess
import re
import sys
import rdflib
import lib_webserv
import lib_common
from lib_properties import pc

if not 'win' in sys.platform:
	lib_common.ErrorMessageHtml("Windows directory changes")

# http://timgolden.me.uk/python/win32_how_do_i/watch_directory_for_changes.html#use_findfirstchange

try:
	import win32file
	import win32con
except ImportError:
	lib_common.ErrorMessageHtml("win32 Python library not installed")


# Ca marche.
# Probleme: En avoir un seul pour tout un disque, ou bien plusieurs ?
# En tout cas les triplets RDF doivent etre les memes de facon a ce que la fusion
# supprime les doublons.

# Ce sera encore plus spectaculaire en Javascript: Il faut qu'on voie 
# les fichiers apparaitre et disparaitre.
# Meme logique que les processes d'ailleurs: Comment dire explicitement
# qu'un triplet RDF a disparu? Il faudrait une anti-relation qui serait traitee
# specifiquement par la fusion.

# path_to_watch = cgiEnv.GetId()

def WindDirChangeDeserialize( log_strm, grph, tuple):
	path_to_watch = tuple[0]
	updated_file = tuple[1]
	path_change = tuple[2]

	full_filename = os.path.join (path_to_watch, updated_file)

	split_path = file.split('\\')
	intermediate_path = path_to_watch

	intermediate_node = lib_common.gUriGen.FileUri( intermediate_path )

	for subdir in split_path[1:-1]:
		subpath = intermediate_path + "\\" + subdir
		sub_node = lib_common.gUriGen.FileUri( subpath )
		grph.add( ( intermediate_node, pc.property_directory, sub_node ) )
		intermediate_path = subpath
		intermediate_node = sub_node


	# TODO: Maybe show the intermediate first between this one and the script argument,
	# IF THIS IS NOT ALREADY DONE ?
	node_path = lib_common.gUriGen.FileUri( full_filename )
	grph.add( ( intermediate_node, pc.property_directory, node_path ) )

	grph.add( ( node_path, pc.property_notified_file_change, rdflib.Literal(path_change) ) )


ACTIONS = {
	1 : "Created",
	2 : "Deleted",
	3 : "Updated",
	4 : "Renamed from something",
	5 : "Renamed to something"
}

# Thanks to Claudio Grondi for the correct set of numbers
FILE_LIST_DIRECTORY = 0x0001

def WindDirChangeEngine(sharedTupleQueue,entityId):

	hDir = win32file.CreateFile (
		entityId,
		FILE_LIST_DIRECTORY,
		win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
		None,
		win32con.OPEN_EXISTING,
		win32con.FILE_FLAG_BACKUP_SEMANTICS,
		None
	)
	while True:
		#
		# ReadDirectoryChangesW takes a previously-created
		# handle to a directory, a buffer size for results,
		# a flag to indicate whether to watch subtrees and
		# a filter of what changes to notify.
		#
		# NB Tim Juchcinski reports that he needed to up
		# the buffer size to be sure of picking up all
		# events when a large number of files were
		# deleted at once.
		#
		results = win32file.ReadDirectoryChangesW (
			hDir,
			1024,
			True,
			win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
			 win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
			 win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
			 win32con.FILE_NOTIFY_CHANGE_SIZE |
			 win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
			 win32con.FILE_NOTIFY_CHANGE_SECURITY,
			None,
			None
		)
		for action, updated_file in results:
			sharedTupleQueue.put( [ path_to_watch, updated_file , ACTIONS.get (action, "Unknown") ] )

if __name__ == '__main__':
	lib_webserv.DoTheJob(WindDirChangeEngine,WindDirChangeDeserialize,__file__,"Directory updates events")
