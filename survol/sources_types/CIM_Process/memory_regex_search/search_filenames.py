#!/usr/bin/env python

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

SlowScript = True

class FilenameParserLinux:
	# https://stackoverflow.com/questions/1976007/what-characters-are-forbidden-in-windows-and-linux-directory-names
	# This is a most plausible regular expressions.
	# Most file names do not contain UTF-8 characters, are not "too long" nor "too short".
	def Regex(self,miniDepth,withRelat):

		rgxFilNam = ""
		# rgxFilNam += "/[^/]+" * miniDepth
		# rgxFilNam += "/[a-zA-Z0-9]+" * miniDepth
		rgxFilNam += r"/[-a-zA-Z0-9\._\+]{3,50}" * miniDepth
		#rgxFilNam = "kademlia"
		return rgxFilNam

	def Cleanup(self,aFilNam):
		return aFilNam

class FilenameParserWindows:
	# Beware that slash-separated filenames are also legal in Windows.
	# https://msdn.microsoft.com/en-us/library/windows/desktop/aa365247(v=vs.85).aspx
	def Regex(self,miniDepth,withRelat):
		rgxFilNam = "[^a-zA-Z][A-Z]:"

		# In Windows, the last character should not be a space or a dot.
		# There must be at least one character.
		oneRegexNormal = r'[^\\/<>:"\|\*\?]+[^. ]'
		# Dot is allowed for current or parent directory
		oneRegexNoSlash = "(" + oneRegexNormal + r"|\.\.|\.)"
		oneRegex = r"[/\\]" + oneRegexNoSlash

		rgxFilNam += oneRegex * miniDepth
		rgxFilNam += oneRegex

		return rgxFilNam

	def Cleanup(self,aFilNam):

		# Truncate first character, because not in the regex.
		aFilNam = aFilNam[1:]

		# file() argument 1 must be encoded string without NULL bytes, not str
		idxZero = aFilNam.find('\0')
		if idxZero >= 0:
			aFilNam = aFilNam[:idxZero]
		return aFilNam

def FilenameParserFunc():
	if lib_util.isPlatformLinux:
		return FilenameParserLinux()
	if lib_util.isPlatformWindows:
		return FilenameParserWindows()
	lib_common.ErrorMessageHtml("No operating system")


def Main():
	# Parameter for the minimal depth of the regular expression.
	# min=3, otherwise any string with a "/" will match.
	keyMiniDepth = "Minimum filename depth"

	# Otherwise, only look for absolute filenames.
	keyWithRelative = "Search relative filenames"

	keyCheckExistence = "Check file existence"

	cgiEnv = lib_common.CgiEnv( parameters = { keyMiniDepth : 3, keyWithRelative : False, keyCheckExistence : True })

	pidint = int( cgiEnv.GetId() )

	paramMiniDepth = int(cgiEnv.GetParameters( keyMiniDepth ))
	paramWithRelative = bool(cgiEnv.GetParameters( keyWithRelative ))
	paramCheckExistence = bool(cgiEnv.GetParameters( keyCheckExistence ))


	grph = cgiEnv.GetGraph()

	node_process = lib_common.gUriGen.PidUri(pidint)

	try:
		objParser = FilenameParserFunc()
		rgxFilNam = objParser.Regex(paramMiniDepth,paramWithRelative)
		DEBUG("rgxFilNam=%s",rgxFilNam)

		resuFilNams = memory_regex_search.GetRegexMatches(pidint,rgxFilNam)

		# This avoids duplicates.
		resuClean = set()

		# The file names which are detected in the process memory might be broken, invalid etc...
		# Only some of them are in valid strings. The other may come from deallocated memory etc...
		for idxFilNam in resuFilNams:
			aFilNam = resuFilNams[idxFilNam]

			# Depending opn the regular expression, the result must be adapted.
			aFilNam = objParser.Cleanup(aFilNam)

			if aFilNam in resuClean:
				continue

			# The file must exist. If we cannot access it does not matter.
			# TODO: Must accept if we can access it or not.
			if paramCheckExistence:

				# TODO: Test existence of relative files by prefixing with current directory.
				try:
					oFil = open(aFilNam,"r")
				except:
					exc = sys.exc_info()[1]
					WARNING("open:%s throw:%s",aFilNam,str(exc))
					continue
				if not oFil:
					continue

				oFil.close()


			resuClean.add( aFilNam )

		for aFilNam in resuClean:
			DEBUG("aFilNam=%s",aFilNam)
			nodeFilnam = lib_common.gUriGen.FileUri( aFilNam )
			grph.add( ( node_process, pc.property_rdf_data_nolist1, nodeFilnam ) )

	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Error:%s. Protection ?"%str(exc))

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()

