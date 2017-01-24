"""
AC2 configuration
"""

import sys
import lib_common
import rdflib
import xml.dom.minidom
import lib_uris
from lib_properties import pc

from sources_types.AC2 import application as survol_AC2_application

def EntityOntology():
	return ( ["File"], )

# Ambiguity with tables, oracle or normal users.
def MakeUri(configFilename,componentName):
	return lib_common.gUriGen.UriMakeFromDict("AC2/configuration", { "File" : configFilename } )

def AddInfo(grph,node,entity_ids_arr):
	DisplayConfigNodes(grph,node,entity_ids_arr[0])

def EntityName(entity_ids_arr,entity_host):
	return entity_ids_arr[0]


# <?xml version="1.0" encoding="utf-8" standalone="yes"?>
# <apps>
#     <hosts>
#         <host hostid="LOCAL"
#               host="127.0.0.1"
#               port="12567"/>
#     </hosts>
#     <app name="AC2-App-Sample-A"
#          version="Version-1"
#          notifref="AC2-App-Sample-A notification rule"
#          cronref="AC2-App-Sample-A scheduling">
def DisplayConfigNodes(grph,configNode,configName):
	# Because of Windows: "C:/AC2\Application_Sample.xml"
	configFile = configName.replace("\\","/")

	sys.stderr.write("configFile=%s configNode=%s\n"%(configFile,str(configNode)))

	dom = xml.dom.minidom.parse(configFile)

	for elt_apps in dom.getElementsByTagName('apps'):
		sys.stderr.write("Founds apps\n")

		for elt_app in dom.getElementsByTagName('app'):
			attr_name = elt_app.getAttributeNode('name').value
			attr_version = elt_app.getAttributeNode('version').value
			attr_notifref = elt_app.getAttributeNode('notifref').value
			attr_cronref = elt_app.getAttributeNode('cronref').value

			nodeApp = survol_AC2_application.MakeUri(configName,attr_name)
			grph.add( ( nodeApp, lib_common.MakeProp("version"), rdflib.Literal( attr_version ) ) )
			grph.add( ( nodeApp, lib_common.MakeProp("notifref"), rdflib.Literal( attr_notifref ) ) )
			grph.add( ( nodeApp, lib_common.MakeProp("cronref"), rdflib.Literal( attr_cronref ) ) )

			grph.add( ( configNode, lib_common.MakeProp("AC2 application"), rdflib.Literal( nodeApp ) ) )

		for elt_hosts in dom.getElementsByTagName('hosts'):
			for elt_host in dom.getElementsByTagName('host'):
				attr_hostid = elt_host.getAttributeNode('hostid').value
				attr_host = elt_host.getAttributeNode('host').value
				attr_port = elt_host.getAttributeNode('port').value

				nodeAddr = lib_common.gUriGen.AddrUri(attr_host,attr_port)
				grph.add( ( nodeAddr, lib_common.MakeProp("Hostid"), rdflib.Literal( attr_hostid ) ) )

				grph.add( ( configNode, lib_common.MakeProp("AC2 host"), rdflib.Literal( nodeAddr ) ) )


	return