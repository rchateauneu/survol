#!/usr/bin/python

"""
WMI portal
"""

import lib_wmi
import lib_common
from lib_properties import pc

def Main():

	# This can process remote hosts because it does not call any script, just shows them.
	cgiEnv = lib_common.CgiEnv(can_process_remote = True)

	grph = cgiEnv.GetGraph()

	entity_type = cgiEnv.m_entity_type
	entity_host = cgiEnv.GetHost()
	entity_host = lib_wmi.NormalHostName(entity_host)


	# TODO: We may also loop on all machines which may describe this object.
	wmiurl = lib_wmi.GetWmiUrl( entity_host, "", "", "" )
	if not wmiurl is None:
		wmiNode = lib_common.NodeUrl(wmiurl)

		hostNode = lib_common.gUriGen.HostnameUri( entity_host )
		grph.add( ( hostNode, pc.property_information, wmiNode ) )
	else:
		lib_common.ErrorMessageHtml("WMI module not installed\n" )

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
