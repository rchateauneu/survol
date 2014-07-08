#!/usr/bin/python

# List of the symbolic links this file point to.
# It checks if qny of the intermediate directories of the file path
# is a symbolic link, and therefore make a recursive walk.

import os
import re
import sys
import cgi
import rdflib

import lib_common
from lib_common import pc
from rdflib import URIRef, BNode, Literal

grph = rdflib.Graph()

arguments = cgi.FieldStorage()
file_path = arguments["entity_id"].value
# file_path = "/home/rchateau/Developpement/ReverseEngineeringApps/PythonStyle/test/l2/l3/t4"

def DoTheRest( beginning, physical, file_split ):
	# print("beginning=" + beginning)
	# print("physical=" + physical)
	# print("file_split=" + str(file_split))
	file_depth = len(file_split)

	if file_depth == 0:
		if beginning != physical:
			nodeLink = lib_common.FileUri( beginning )
			nodePhys = lib_common.FileUri( physical )
			grph.add( ( nodeLink, pc.property_symlink, nodePhys ) )
		return

	ext = "/" + file_split[0]
	DoTheRest( beginning + ext, physical + ext, file_split[ 1 : ] )

	try:
		new_begin = beginning + ext
		# print("Test symlink:" + new_begin)
		lnk_path = os.readlink( new_begin )

		# BEWARE, the link is absolute or relative.
		# It's a bit nonsensical because it depends on the current path.
		if lnk_path[0] == '/':
			full_path = lnk_path
		else:
			full_path = beginning + "/" + lnk_path
		# print("link=" + lnk_path + "=>" + full_path)
		DoTheRest( full_path, physical + ext, file_split[ 1 : ] )
	except OSError:
		# print("Not a symlink:"+beginning)
		return

################################################################################

try:
	file_split = file_path.split('/')
	# print("file_split=" + str(file_split))
	# This assumes that file_path is absolute and begins with a slash.
	DoTheRest( "", "", file_split[ 1: ] )
except Exception, exc:
	lib_common.ErrorMessageHtml("Error:"+str(exc))

lib_common.OutCgiRdf(grph)

