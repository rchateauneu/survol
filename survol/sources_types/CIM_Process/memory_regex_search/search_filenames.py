#!/usr/bin/python

"""
File names in process memory.

Filenames detected in the running process'memory.
"""

import os
import sys

import lib_util
import lib_common
from lib_properties import pc

from sources_types import CIM_Process
from sources_types.CIM_Process import memory_regex_search

# https://stackoverflow.com/questions/1976007/what-characters-are-forbidden-in-windows-and-linux-directory-names

def FilenameRegexLinux(miniDepth,withRelat):
	rgxFilNam = ""

	rgxFilNam += "/[^/]+" * miniDepth
	return rgxFilNam

# Beware that slash-separated filenames are also legal in Windows.
# https://msdn.microsoft.com/en-us/library/windows/desktop/aa365247(v=vs.85).aspx
def FilenameRegexWindows(miniDepth,withRelat):
	rgxFilNam = "[^a-zA-Z][A-Z]:"

	# In Windows, the last character should not be a space or a dot.
	# There must be at least one character.
	oneRegexNormal = '[^\\/<>:"\|\*\?\0]+[^. ]'
	# Dot is allowed for current or parent directory
	oneRegexNoSlash = "(" + oneRegexNormal + "|\.\.|\.)"
	oneRegex = r"[/\\]" + oneRegexNoSlash

	rgxFilNam += oneRegex * miniDepth

	return rgxFilNam

def FilenameRegexFunc():
	if lib_util.isPlatformLinux:
		return FilenameRegexLinux
	if lib_util.isPlatformWindows:
		return FilenameRegexWindows
	lib_common.ErrorMessageHtml("No operating system")


def Main():
	# Parameter for the minimal depth of the regular expression.
	# min=3, otherwise any string with a "/" will match.
	paramkeyMiniDepth = "Minimum filename depth"

	# Otherwise, only look for absolute filenames.
	paramkeyWithRelative = "Search relative filenames"

	cgiEnv = lib_common.CgiEnv( parameters = { paramkeyMiniDepth : 3, paramkeyWithRelative : False })

	pidint = int( cgiEnv.GetId() )

	paramMiniDepth = int(cgiEnv.GetParameters( paramkeyMiniDepth ))
	paramWithRelative = bool(cgiEnv.GetParameters( paramkeyWithRelative ))


	grph = cgiEnv.GetGraph()

	node_process = lib_common.gUriGen.PidUri(pidint)

	try:
		rgxFunc = FilenameRegexFunc()
		rgxFilNam = rgxFunc(paramMiniDepth,paramWithRelative)
		sys.stderr.write("rgxFilNam=%s\n"%rgxFilNam)

		resuFilNams = memory_regex_search.GetRegexMatches(pidint,rgxFilNam)

		# This avoids duplicates.
		resuClean = set()

		# The file names which are detected in the process memory might be broken, invalid etc...
		# Only some of them are in valid strings. The other may come from deallocated memory etc...
		for idxFilNam in resuFilNams:
			aFilNam = resuFilNams[idxFilNam]

			# Truncate first character, because not in the regex.
			aFilNam = aFilNam[1:]

			# file() argument 1 must be encoded string without NULL bytes, not str
			idxZero = aFilNam.find('\0')
			if idxZero >= 0:
				aFilNam = aFilNam[:idxZero]

			aFilNam=str(aFilNam) # On Python3, this is a bytes array.

			if aFilNam in resuClean:
				continue

			# The file must exist. If we cann access it does not matter.
			# TODO: Must accept if we can access it or not.
			try:
				oFil = open(aFilNam,"r")
			except:
				exc = sys.exc_info()[1]
				# sys.stderr.write("open:%s throw:%s\n"%(aFilNam,str(exc)))

				# If the file cannot be opened, it may be a PATH of several filenames
				# separated by a semi-colon ";".
				continue
			if not oFil:
				continue

			oFil.close()

			resuClean.add( aFilNam )

		for aFilNam in resuClean:
			# sys.stderr.write("aFilNam=%s\n"%aFilNam)
			nodeFilnam = lib_common.gUriGen.FileUri( aFilNam )
			grph.add( ( node_process, pc.property_rdf_data_nolist1, nodeFilnam ) )

	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Error:%s. Protection ?"%str(exc))

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()

