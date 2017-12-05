#!/usr/bin/python

"""
File names in process memory.
"""

import os
import sys

import lib_util
import lib_common
from lib_properties import pc

from sources_types import CIM_Process
from sources_types.CIM_Process import memory_regex_search

def Main():
	cgiEnv = lib_common.CgiEnv()
	pidint = int( cgiEnv.GetId() )

	grph = cgiEnv.GetGraph()

	node_process = lib_common.gUriGen.PidUri(pidint)

	try:
		# TODO: These two regular expressions must be fixed.
		if lib_util.isPlatformLinux:
			# https://techtavern.wordpress.com/2009/04/06/regex-that-matches-path-filename-and-extension/
			rgxFilNam = "[^/]/.*"
		elif lib_util.isPlatformLinux:
			rgxFilNam = "[^a-zA-Z][A-Z]:\\*"
		else:
			lib_common.ErrorMessageHtml("No operating system")

		resuFilNams = memory_regex_search.GetRegexMatches(pidint,rgxFilNam)

		# This avoids duplicates.
		resuClean = set()

		# The file names which are detected in the process memory might be broken, invalid etc...
		# Only some of them are in valid strings. The other may come from deallocated memory etc...
		for idxFilNam in resuFilNams:
			aFilNam = resuFilNams[idxFilNam]
			aFilNam=str(aFilNam) # On Python3, this is a bytes array.

			if aFilNam in resuClean:
				continue

			# The file must exist. It is debattable whether this process
			# can access it or not.
			oFil = open(aFilNam,"r")
			if not oFil:
				continue

			oFil.close()


			resuClean.add( aFilNam )

		for aFilNam in resuClean:
			# sys.stderr.write("aFilNam=%s\n"%aFilNam)
			nodeFilnam = lib_util.FileUri( aFilNam )
			grph.add( ( node_process, pc.property_rdf_data_nolist1, nodeFilnam ) )

	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Error:%s. Protection ?"%str(exc))

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()

