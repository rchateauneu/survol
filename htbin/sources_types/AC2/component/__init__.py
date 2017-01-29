"""
AC2 component
"""

import os
import rdflib
import lib_common
from lib_properties import pc
from sources_types import AC2
from sources_types.AC2 import application as AC2_application

def Graphic_colorbg():
	return "#88BB88"

def EntityOntology():
	return ( ["File", "App", "Comp"], )

def MakeUri(configFilename,applicationName,componentName):
	return lib_common.gUriGen.UriMakeFromDict("AC2/component", { "File" : configFilename, "App" : applicationName, "Comp" : componentName } )

def AddInfo(grph,node,entity_ids_arr):
	ac2File = entity_ids_arr[0]
	ac2App = entity_ids_arr[1]

	appNode = AC2_application.MakeUri(ac2File,ac2App)
	# Should be the other way around but not nice to display.
	grph.add( ( node, AC2.propComp2App, appNode ) )


# Pointer vers le HOST en parsant le fichier de conf.


def EntityName(entity_ids_arr,entity_host):
	return AC2.ConfigFileNameClean(entity_ids_arr[0]) + "." + entity_ids_arr[1] + "." + entity_ids_arr[2]

def AddPropIfThere(grph,compNode,elt_component,propNamXml,propRdf):
	attr_xml = elt_component.getAttributeNode(propNamXml)
	if attr_xml:
		grph.add( ( compNode, propRdf, rdflib.Literal( attr_xml.value ) ) )

def DecorateComponentWithXml(grph,compNode,elt_component):

	AddPropIfThere(grph,compNode,elt_component,'description',pc.property_information)

	for prpNam in ["group","type","retryNumber","checkFrequency","redirectoutput","type"]:
		AddPropIfThere(grph,compNode,elt_component,prpNam,lib_common.MakeProp(prpNam))


	# <component name="A1.1"
	# 		   description="A1.1 component"
	# 		   group="A group"
	# 		   hostref="LOCAL"
	# 		   authref="LOCAL"
	# 		   retryNumber="3"
	# 		   checkFrequency="20"
	# 		   redirectoutput="false"
	# 		   type="browser">