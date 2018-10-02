#!/usr/bin/python

"""
AC2 component state / status script.
"""

import sys
import lib_common
import lib_util
import lib_uris
from lib_properties import pc
from sources_types import AC2
from sources_types.AC2 import configuration as AC2_configuration
from sources_types.AC2 import component as AC2_component
from sources_types.AC2 import application as AC2_application

def ComponentNameToNode(configName,appName,componentName):
	try:
		return ComponentNameToNode.NodeMap[componentName]
	except KeyError:
		nodeComponent = AC2_component.MakeUri(configName,appName,componentName)
		ComponentNameToNode.NodeMap[componentName] = nodeComponent
		return nodeComponent

ComponentNameToNode.NodeMap = {}

def DisplayComponentDependencies(grph,ac2File,ac2App,ac2Comp):
	configNode = AC2_configuration.MakeUri(ac2File)
	appNode = AC2_application.MakeUri(ac2File,ac2App)
	compNode = AC2_component.MakeUri(ac2File,ac2App,ac2Comp)

	dom = AC2_configuration.GetDom(ac2File)

	# TODO: PROBLEME, ON DEVRAIT ALLER CHERCHER LES SOUS-NODES AU LIEU DE TOUT REPARCOURIR !!!!!!!!!!!
	for elt_apps in dom.getElementsByTagName('apps'):
		DEBUG("Founds apps")

		# TODO: ERROR: SHOULD FOCUS ON ONE APP ONLY.

		for elt_app in elt_apps.getElementsByTagName('app'):
			attr_app_name = elt_app.getAttributeNode('name').value
			DEBUG("attr_app_name=%s",attr_app_name)

			if attr_app_name != ac2App:
				continue

			AC2_application.DecorateAppWithXml(grph,appNode,elt_app)

			for elt_component in elt_app.getElementsByTagName('component'):
				attr_component_name = elt_component.getAttributeNode('name').value

				DEBUG("attr_component_name=%s",attr_component_name)

				if attr_component_name == ac2Comp:
					AC2_component.DecorateComponentWithXml(grph,compNode,elt_component)

					fatherFound = False
					for elt_father in elt_component.getElementsByTagName('father'):
						# There should be one parent only.
						attr_father_name = elt_father.firstChild.nodeValue
						DEBUG("attr_father_name=%s",attr_father_name)
						nodeFather = ComponentNameToNode(ac2File,attr_app_name,attr_father_name)

						grph.add( ( nodeFather, AC2.propParent, compNode ) )
						fatherFound = True

					if fatherFound:
						# grph.add( ( appNode, AC2.propComp2App, nodeFather ) )
						grph.add( ( nodeFather, AC2.propComp2App, appNode ) )
						grph.add( ( nodeFather, AC2.propParent, compNode ) )
					else:
						# grph.add( ( appNode, AC2.propComp2App, compNode ) )
						grph.add( ( compNode, AC2.propComp2App, appNode ) )

					break

	return



def Main():

	cgiEnv = lib_common.CgiEnv()

	ac2File = cgiEnv.m_entity_id_dict["File"]
	ac2App = cgiEnv.m_entity_id_dict["App"]
	ac2Comp = cgiEnv.m_entity_id_dict["Comp"]

	DEBUG("ac2File=%s ac2App=%s ac2Comp=%s", ac2File,ac2App,ac2Comp)

	grph = cgiEnv.GetGraph()

	DisplayComponentDependencies(grph,ac2File,ac2App,ac2Comp)

	cgiEnv.OutCgiRdf( "LAYOUT_RECT", [AC2.propParent] )

if __name__ == '__main__':
	Main()
