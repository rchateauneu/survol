#!/usr/bin/python

"""
AC2 components tree
"""

import sys
import lib_common
import lib_util
import lib_uris
from sources_types import AC2
from sources_types.AC2 import configuration as AC2_configuration
from sources_types.AC2 import component as AC2_component
from sources_types.AC2 import application as AC2_application

from lib_properties import pc

# <?xml version="1.0" encoding="utf-8" standalone="yes"?>
# <apps>
#    <app name="AC2-App-Sample-A"
#         version="Version-1"
#         notifref="AC2-App-Sample-A notification rule"
#         cronref="AC2-App-Sample-A scheduling">
#        <component name="A1.1"
#                   description="A1.1 component"
#                   group="A group"
#                   hostref="LOCAL"
#                   authref="LOCAL"
#                   retryNumber="3"
#                   checkFrequency="20"
#                   redirectoutput="false"
#                   type="browser">
#            <father>A1</father>
#            <action value="C:\Strawberry\perl\bin\perl.exe C:\AC2\scripts\xcapp-file.pl check app-A-component-1.1" name="check"/>
#            <action value="C:\Strawberry\perl\bin\perl.exe C:\AC2\scripts\xcapp-file.pl enable appA-component-1.1"
#                    name="enable"
#                    retryTime="60"/>
#            <action value="C:\Strawberry\perl\bin\perl.exe C:\AC2\scripts\xcapp-file.pl disable app-A-component-1.1" name="disable" retryTime="60"/>
#        </component>

def ComponentNameToNode(configName,appName,componentName):
	try:
		return ComponentNameToNode.NodeMap[componentName]
	except KeyError:
		nodeComponent = AC2_component.MakeUri(configName,appName,componentName)
		ComponentNameToNode.NodeMap[componentName] = nodeComponent
		return nodeComponent

ComponentNameToNode.NodeMap = {}

def DisplayComponentsTree(grph,configName,ac2App):
	dom = AC2_configuration.GetDom(configName)

	configNode = AC2_configuration.MakeUri(configName)

	# TODO: PROBLEME, ON DEVRAIT ALLER CHERCHER LES SOUS-NODES AU LIEU DE TOUT REPARCOURIR !!!!!!!!!!!
	for elt_apps in dom.getElementsByTagName('apps'):
		# There should be one only.
		sys.stderr.write("Founds apps\n")

		for elt_app in elt_apps.getElementsByTagName('app'):
			attr_name = elt_app.getAttributeNode('name').value
			DEBUG("attr_name=%s",attr_name)

			if attr_name != ac2App:
				continue

			appNode = AC2_application.MakeUri(configName,attr_name)

			AC2_application.DecorateAppWithXml(grph,appNode,elt_app)

			for elt_component in elt_app.getElementsByTagName('component'):
				attr_component_name = elt_component.getAttributeNode('name').value
				nodeComponent = ComponentNameToNode(configName,attr_name,attr_component_name)

				DEBUG("attr_component_name=%s",attr_component_name)

				AC2_component.DecorateComponentWithXml(grph,nodeComponent,elt_component)

				fatherFound = False
				for elt_father in elt_component.getElementsByTagName('father'):
					attr_father_name = elt_father.firstChild.nodeValue
					DEBUG("attr_father_name=%s",attr_father_name)
					nodeFather = ComponentNameToNode(configName,attr_name,attr_father_name)

					grph.add( ( nodeFather, AC2.propParent, nodeComponent ) )
					fatherFound = True

				if not fatherFound:
					grph.add( ( appNode, AC2.propParent, nodeComponent ) )

def Main():

	cgiEnv = lib_common.CgiEnv()

	ac2File = cgiEnv.m_entity_id_dict["File"]

	ac2App = cgiEnv.m_entity_id_dict["App"]

	sys.stderr.write("ac2File=%s ac2App=%s\n"% (ac2File,ac2App) )

	grph = cgiEnv.GetGraph()

	DisplayComponentsTree(grph,ac2File,ac2App)

	cgiEnv.OutCgiRdf( "LAYOUT_RECT", [AC2.propParent] )

if __name__ == '__main__':
	Main()

