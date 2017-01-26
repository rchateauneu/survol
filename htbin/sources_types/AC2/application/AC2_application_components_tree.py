#!/usr/bin/python

"""
AC2 components tree
"""

import sys
import rdflib
import lib_common
import lib_util
import lib_uris
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

def DisplayComponentsTree(grph,configNode,configName,appNode,ac2App):
	dom = AC2_configuration.GetDom(configName)

	# TODO: PROBLEME, ON DEVRAIT ALLER CHERCHER LES SOUS-NODES AU LIEU DE TOUT REPARCOURIR !!!!!!!!!!!
	for elt_apps in dom.getElementsByTagName('apps'):
		sys.stderr.write("Founds apps\n")

		# TODO: ERROR: SHOULD FOCUS ON ONE APP ONLY.

		for elt_app in elt_apps.getElementsByTagName('app'):
			attr_name = elt_app.getAttributeNode('name').value
			attr_version = elt_app.getAttributeNode('version').value
			attr_notifref = elt_app.getAttributeNode('notifref').value
			attr_cronref = elt_app.getAttributeNode('cronref').value

			sys.stderr.write("attr_name=%s\n"%attr_name)

			appNode = AC2_application.MakeUri(configName,attr_name)

			for elt_component in elt_app.getElementsByTagName('component'):
				attr_component_name = elt_component.getAttributeNode('name').value
				nodeComponent = ComponentNameToNode(configName,attr_name,attr_component_name)

				sys.stderr.write("attr_component_name=%s\n"%attr_component_name)

				attr_component_description = elt_component.getAttributeNode('description')
				if attr_component_description:
					grph.add( ( nodeComponent, pc.property_information, rdflib.Literal( attr_component_description.value ) ) )

				fatherFound = False
				for elt_father in elt_component.getElementsByTagName('father'):
					# attr_father_name = str(elt_father)
					attr_father_name = elt_father.firstChild.nodeValue
					sys.stderr.write("dir=%s\n"%dir(elt_father))
					sys.stderr.write("attr_father_name=%s\n"%attr_father_name)
					nodeFather = ComponentNameToNode(configName,attr_name,attr_father_name)

					grph.add( ( nodeFather, lib_common.MakeProp("parent"), nodeComponent ) )
					fatherFound = True

				if not fatherFound:
					grph.add( ( appNode, lib_common.MakeProp("parent"), nodeComponent ) )

def Main():

	cgiEnv = lib_common.CgiEnv()

	ac2File = cgiEnv.m_entity_id_dict["File"]

	ac2App = cgiEnv.m_entity_id_dict["App"]

	sys.stderr.write("ac2File=%s ac2App=%s\n"% (ac2File,ac2App) )

	grph = rdflib.Graph()

	configNode = AC2_configuration.MakeUri(ac2File)
	appNode = AC2_application.MakeUri(ac2File,ac2App)

	DisplayComponentsTree(grph,configNode,ac2File,appNode,ac2App)

	cgiEnv.OutCgiRdf(grph )

if __name__ == '__main__':
	Main()

