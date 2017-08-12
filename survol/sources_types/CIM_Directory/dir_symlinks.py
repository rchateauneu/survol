#!/usr/bin/python

"""
Symbolic link destination (Recursive)
"""

# List of the symbolic links this file point to.
# It checks if qny of the intermediate directories of the file path
# is a symbolic link, and therefore make a recursive walk.

import os
import re
import sys
from sources_types import CIM_DataFile
import lib_common
from lib_properties import pc

def DoTheRest( grph, beginning, physical, file_split ):
	file_depth = len(file_split)

	if file_depth == 0:
		if beginning != physical:
			nodePhys = lib_common.gUriGen.FileUri( physical )
			CIM_DataFile.AddInfo( grph, nodePhys, [ physical ] )
			nodeLink = lib_common.gUriGen.FileUri( beginning )
			CIM_DataFile.AddInfo( grph, nodeLink, [ beginning ] )
			grph.add( ( nodePhys, pc.property_symlink, nodeLink ) )
		return

	ext = "/" + file_split[0]
	DoTheRest( grph, beginning + ext, physical + ext, file_split[ 1 : ] )

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
		DoTheRest( grph, full_path, physical + ext, file_split[ 1 : ] )
	except OSError:
		# print("Not a symlink:"+beginning)
		return

################################################################################

def Main():
	cgiEnv = lib_common.CgiEnv()
	file_path = cgiEnv.GetId()

	grph = cgiEnv.GetGraph()

	try:
		file_split = file_path.split('/')
		# print("file_split=" + str(file_split))
		# This assumes that file_path is absolute and begins with a slash.
		DoTheRest( grph, "", "", file_split[ 1: ] )
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Error:"+str(exc))

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
