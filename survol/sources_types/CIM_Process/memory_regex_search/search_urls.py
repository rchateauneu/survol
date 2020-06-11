#!/usr/bin/env python

"""
Scan process for HTTP urls.
"""

import os
import sys

import lib_util
import lib_common
from lib_properties import pc

from sources_types import CIM_Process
from sources_types.CIM_Process import memory_regex_search

SlowScript = True

def Main():
	cgiEnv = lib_common.CgiEnv()
	pidint = int( cgiEnv.GetId() )

	grph = cgiEnv.GetGraph()

	node_process = lib_common.gUriGen.PidUri(pidint)

	try:
		# http://daringfireball.net/2010/07/improved_regex_for_matching_urls
		# rgxHttp = "http://[a-zA-Z_0-9\.]*"
		rgxHttp = r"http://[a-z_0-9\.]*"

		resuUrls = memory_regex_search.GetRegexMatches(pidint,rgxHttp)

		resuClean = set()

		# The URLs which are detected in the process memory might be broken, invalid etc...
		# Only some of them are in valid strings. The other may come from deallocated memory etc...
		for urlIdx in resuUrls:
			urlHttp = resuUrls[urlIdx]
			# In memory, we find strings such as "http://adblockplus.orgzzzzzzzzzzzz"
			# or "http://adblockplus.orgzzzzzzzzzzzz"
			# "activistpost.netzx"
			urlHttp=str(urlHttp) # On Python3, this is a bytes array.
			splitDots = urlHttp.split(".")
			topLevel = splitDots[-1]
			# Primitive way to remove apparently broken URLs.
			if( len(topLevel) > 4 ):
				continue
			resuClean.add( urlHttp )

		for urlHttp in resuClean:
			# sys.stderr.write("urlHttp=%s\n"%urlHttp)
			nodePortalWbem = lib_common.NodeUrl( urlHttp )
			grph.add( ( node_process, pc.property_rdf_data_nolist1, nodePortalWbem ) )

	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Error:%s. Protection ?"%str(exc))

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()

