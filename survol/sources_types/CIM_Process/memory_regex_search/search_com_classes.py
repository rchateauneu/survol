#!/usr/bin/python

"""
Scan process for COM classes
"""

import os
import sys

import lib_util
import lib_common
from lib_properties import pc
import lib_com_type_lib

from sources_types import CIM_Process
from sources_types.CIM_Process import memory_regex_search

def Main():
	cgiEnv = lib_common.CgiEnv()
	pidint = int( cgiEnv.GetId() )

	grph = cgiEnv.GetGraph()

	node_process = lib_common.gUriGen.PidUri(pidint)

	try:
		rgxHttp = r"\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}"

		resuComClasses = memory_regex_search.GetRegexMatches(pidint,rgxHttp)

		resuClean = set()

		propComClass = lib_common.MakeProp("COM class")
		for classIdx in resuComClasses:
			comClassId = resuComClasses[classIdx]
			# On Python3, this is a bytes which must be converted to str.
			comClassId = str(comClassId)

			# comClass = "{DB7A405D-208F-4E88-BA0A-132ACFA0B5B6}" for example.
			typelibNode = lib_common.gUriGen.ComRegisteredTypeLibUri( comClassId )
			grph.add( ( node_process, propComClass, typelibNode ) )

	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Error:%s. Protection ?"%str(exc))

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()

