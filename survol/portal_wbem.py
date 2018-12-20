#!/usr/bin/python

"""
WBEM portal
"""

import sys
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
	hostId = cgiEnv.GetId()
	DEBUG("entity_host=%s entity_type=%s hostname=%s",entity_host,entity_type,hostId)

	wbem_urls_list = lib_wbem.GetWbemUrlsTyped( entity_host, nameSpace, entity_type, hostId )

	# Maybe some of these servers are not able to display anything about this object.
	for ( url_wbem, wbemHost ) in wbem_urls_list:
		DEBUG("url_wbem=%s wbemHost=%s",url_wbem,wbemHost)
		wbemNode = lib_common.NodeUrl(url_wbem)
		hostNode = lib_common.gUriGen.HostnameUri( wbemHost )
		grph.add( ( hostNode, pc.property_information, wbemNode ) )

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
