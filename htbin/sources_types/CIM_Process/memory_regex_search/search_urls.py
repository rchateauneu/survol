#!/usr/bin/python

"""
Scan process for HTTP urls.
"""

import os
import sys
import rdflib

# Does not work with Apache and Windows: ImportError: No module named revlib
#from revlib import lib_util
#from revlib import lib_common
#from revlib.lib_properties import pc

# This works on Windows, with Apache and cgiserver.py
import lib_util
import lib_common
from lib_properties import pc

import lib_entities.lib_entity_CIM_Process as lib_entity_CIM_Process

from sources_types import CIM_Process
from sources_types.CIM_Process import memory_regex_search

def Main():
	cgiEnv = lib_common.CgiEnv()
	pidint = int( cgiEnv.GetId() )

	grph = rdflib.Graph()

	# proc_obj = lib_entity_CIM_Process.PsutilGetProcObj(pidint)

	node_process = lib_common.gUriGen.PidUri(pidint)

	propHttp = lib_common.MakeProp("HTTP url")
	try:
		resu = memory_regex_search.GetRegexMatches(pidint,"http://[a-zA-Z_0-9\.]*")

		for urlHttp in resu:
			grph.add( (node_process, propHttp, rdflib.Literal(urlHttp) ) )

	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Error:%s. Protection ?"%str(exc))


	cgiEnv.OutCgiRdf(grph,[propHttp])

if __name__ == '__main__':
	Main()

