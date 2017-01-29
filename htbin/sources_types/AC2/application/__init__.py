"""
AC2 application
"""

import rdflib
import lib_common
from lib_properties import pc
from sources_types import AC2
from sources_types.AC2 import configuration as AC2_configuration

def Graphic_colorbg():
	return "#FFBBFF"

def EntityOntology():
	return ( ["File", "App"], )

def MakeUri(configFilename,applicationName):
	return lib_common.gUriGen.UriMakeFromDict("AC2/application", { "File" : configFilename, "App" : applicationName } )

def AddInfo(grph,node,entity_ids_arr):
	ac2File = entity_ids_arr[0]
	configNode = AC2_configuration.MakeUri(ac2File)
	propApp2Conf = lib_common.MakeProp("configuration")
	grph.add( ( configNode, propApp2Conf, node ) )
	return

def EntityName(entity_ids_arr,entity_host):
	return AC2.ConfigFileNameClean(entity_ids_arr[0]) + "." + entity_ids_arr[1]

def DecorateAppWithXml(grph,appNode,elt_app):
	attr_version = elt_app.getAttributeNode('version').value
	grph.add( ( appNode, lib_common.MakeProp("Version"), rdflib.Literal( attr_version ) ) )

	attr_notifref = elt_app.getAttributeNode('notifref').value
	grph.add( ( appNode, lib_common.MakeProp("Notifref"), rdflib.Literal( attr_notifref ) ) )

	attr_cronref = elt_app.getAttributeNode('cronref').value
	grph.add( ( appNode, lib_common.MakeProp("Cronref"), rdflib.Literal( attr_cronref ) ) )



