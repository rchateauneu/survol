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

from sources_types import CIM_Process

from sources_types import CIM_Process
from sources_types.CIM_Process import memory_regex_search

def Main():
	cgiEnv = lib_common.CgiEnv()
	pidint = int( cgiEnv.GetId() )

	grph = cgiEnv.GetGraph()

	# proc_obj = CIM_Process.PsutilGetProcObj(pidint)

	node_process = lib_common.gUriGen.PidUri(pidint)

	propHttp = lib_common.MakeProp("HTTP url")
	try:
		# http://daringfireball.net/2010/07/improved_regex_for_matching_urls
		# rgxHttp = "http://[a-zA-Z_0-9\.]*"
		rgxHttp = "http://[a-z_0-9\.]*"

		resu = memory_regex_search.GetRegexMatches(pidint,rgxHttp)

		resuClean = set()
		for urlHttp in resu:
			# In memory, we find strings such as "http://adblockplus.orgzzzzzzzzzzzz"
			# or "http://adblockplus.orgzzzzzzzzzzzz"
			# "activistpost.netzx"
			splitDots = urlHttp.split(".")
			topLevel = splitDots[-1]
			# Primitive way to remove apparently broken URLs.
			if( len(topLevel) > 4 ):
				continue
			resuClean.add( urlHttp )


		for urlHttp in resuClean:
			# grph.add( (node_process, propHttp, rdflib.Literal(urlHttp) ) )
			# sys.stderr.write("urlHttp=%s\n"%urlHttp)
			nodePortalWbem = rdflib.term.URIRef( urlHttp )
			grph.add( ( node_process, pc.property_rdf_data_nolist1, nodePortalWbem ) )


	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Error:%s. Protection ?"%str(exc))


	cgiEnv.OutCgiRdf([propHttp])

if __name__ == '__main__':
	Main()

