#!/usr/bin/python

"""
WBEM portal
"""

import rdflib
import lib_common

try:
	import lib_wbem
except ImportError:
	lib_common.ErrorMessageHtml("WBEM not available")
from lib_properties import pc

def Main():

	# This can process remote hosts because it does not call any script, just shows them.
	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	( nameSpace, className, entity_type ) = cgiEnv.GetNamespaceType()

	entity_host = cgiEnv.GetHost()

	# Maybe some of these servers are not able to display anything about this object.
	# wbem_urls_list = lib_wbem.GetWbemUrls( entity_host, nameSpace, entity_type, "" )
	wbem_urls_list = lib_wbem.GetWbemUrls( "*", nameSpace, entity_type, "" )
	for ( url_wbem, wbemHost ) in wbem_urls_list:
		wbemNode = rdflib.term.URIRef(url_wbem)

		hostNode = lib_common.gUriGen.HostnameUri( wbemHost )
		grph.add( ( hostNode, pc.property_information, wbemNode ) )

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
