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
	sys.stderr.write("entity_host=%s entity_type=%s hostname=%s\n"%(entity_host,entity_type,hostId))

	# The coding of another machine soujnds dodgy but is simple a CIM path.
	if (entity_type == 'CIM_ComputerSystem'):
		# TODO:  hostId="Unknown-30-b5-c2-02-0c-b5-2" does not work.
		wbem_urls_list = lib_wbem.GetWbemUrls( hostId, nameSpace, entity_type, "Name=" + hostId + ".home")
	else:
		## WHY A STAR ????
		wbem_urls_list = lib_wbem.GetWbemUrls( "*", nameSpace, entity_type, "" )

	# Maybe some of these servers are not able to display anything about this object.
	for ( url_wbem, wbemHost ) in wbem_urls_list:
		sys.stderr.write("url_wbem=%s wbemHost=%s\n"%(url_wbem,wbemHost))
		wbemNode = lib_common.NodeUrl(url_wbem)
		hostNode = lib_common.gUriGen.HostnameUri( wbemHost )
		grph.add( ( hostNode, pc.property_information, wbemNode ) )

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
