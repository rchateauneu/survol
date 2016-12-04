import sys
import rdflib
import lib_wmi
import lib_util
import lib_common
from lib_properties import pc


def AddWbemWmiServers(grph,rootNode,entity_host, nameSpace, entity_type, entity_id):
	# sys.stderr.write("AddWbemWmiServers entity_host=%s nameSpace=%s entity_type=%s\n" % (entity_host,nameSpace,entity_type))

	try:
	# Maybe some of these servers are not able to display anything about this object.
		import lib_wbem

		wbem_servers_desc_list = lib_wbem.GetWbemUrls( entity_host, nameSpace, entity_type, entity_id )
		# sys.stderr.write("wbem_servers_desc_list len=%d\n" % len(wbem_servers_desc_list))
		for url_server in wbem_servers_desc_list:
			# TODO: Filter only entity_host
			# sys.stderr.write("url_server=%s\n" % str(url_server))

			if lib_wbem.ValidClassWbem(entity_host, entity_type):
				wbemNode = rdflib.term.URIRef(url_server[0])
				if entity_host:
					txtLiteral = "WBEM url, host=%s class=%s"%(entity_host,entity_type)
				else:
					txtLiteral = "WBEM url, current host, class=%s"%(entity_type)
				grph.add( ( wbemNode, pc.property_information, rdflib.Literal(txtLiteral ) ) )

				grph.add( ( rootNode, pc.property_wbem_data, wbemNode ) )
				wbemHostNode = lib_common.gUriGen.HostnameUri( url_server[1] )
				grph.add( ( wbemNode, pc.property_host, wbemHostNode ) )
				grph.add( ( wbemHostNode, pc.property_information, rdflib.Literal("Url to host") ) )
	except ImportError:
		pass

	if lib_wmi.ValidClassWmi(entity_host, entity_type):
		# TODO: We may also loop on all machines which may describe this object.
		wmiurl = lib_wmi.GetWmiUrl( entity_host, nameSpace, entity_type, entity_id )
		# sys.stderr.write("wmiurl=%s\n" % str(wmiurl))
		if not wmiurl is None:
			wmiNode = rdflib.term.URIRef(wmiurl)
			grph.add( ( rootNode, pc.property_wmi_data, wmiNode ) )
			if entity_host:
				txtLiteral = "WMI url, host=%s class=%s"%(entity_host,entity_type)
			else:
				txtLiteral = "WMI url, current host, class=%s"%(entity_type)
			grph.add( ( wmiNode, pc.property_information, rdflib.Literal(txtLiteral) ) )

			if entity_host:
				nodePortalWmi = lib_util.UrlPortalWmi(entity_host)
				grph.add( ( wmiNode, pc.property_rdf_data_nolist2, nodePortalWmi ) )




# The URL is hard-coded but very important because it allows to visit another host with WMI access.
def AddInfo(grph,node,entity_ids_arr):
    theHostname = entity_ids_arr[0]

    nameSpace = ""
    AddWbemWmiServers(grph,node,theHostname, nameSpace, "CIM_ComputerSystem", "Name="+theHostname)
