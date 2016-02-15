import sys
import rdflib
import lib_wmi
import lib_wbem
import lib_common
from lib_properties import pc


def AddWbemWmiServers(grph,rootNode,entity_host, nameSpace, entity_type, entity_id):
	# Maybe some of these servers are not able to display anything about this object.
	wbem_servers_desc_list = lib_wbem.GetWbemUrls( entity_host, nameSpace, entity_type, entity_id )
	sys.stderr.write("wbem_servers_desc_list len=%d\n" % len(wbem_servers_desc_list))
	for url_server in wbem_servers_desc_list:
		sys.stderr.write("url_server=%s\n" % str(url_server))
		wbemNode = rdflib.term.URIRef(url_server[0])
		grph.add( ( rootNode, pc.property_wbem_data, wbemNode ) )
		wbemHostNode = lib_common.gUriGen.HostnameUri( url_server[1] )
		grph.add( ( wbemNode, pc.property_host, wbemHostNode ) )

	# TODO: We may also loop on all machines which may describe this object.
	wmiurl = lib_wmi.GetWmiUrl( entity_host, nameSpace, entity_type, entity_id )
	sys.stderr.write("wmiurl=%s\n" % str(wmiurl))
	if not wmiurl is None:
		wmiNode = rdflib.term.URIRef(wmiurl)
		grph.add( ( rootNode, pc.property_wmi_data, wmiNode ) )


def AddInfo(grph,node,entity_ids_arr):
    theHostname = entity_ids_arr[0]

    nameSpace = ""
    AddWbemWmiServers(grph,node,theHostname, nameSpace, "CIM_ComputerSystem", theHostname)
