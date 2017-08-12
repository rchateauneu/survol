#!/usr/bin/python

"""
AC2 component dependencies
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
		sys.stderr.write("Founds apps\n")

		# TODO: ERROR: SHOULD FOCUS ON ONE APP ONLY.

		for elt_app in elt_apps.getElementsByTagName('app'):
			attr_app_name = elt_app.getAttributeNode('name').value
			sys.stderr.write("attr_app_name=%s\n"%attr_app_name)

			if attr_app_name != ac2App:
				continue

			AC2_application.DecorateAppWithXml(grph,appNode,elt_app)

			#attr_version = elt_app.getAttributeNode('version').value
			#grph.add( ( appNode, lib_common.MakeProp("Version"), lib_common.NodeLiteral( attr_version ) ) )

			#attr_notifref = elt_app.getAttributeNode('notifref').value
			#grph.add( ( appNode, lib_common.MakeProp("Notifref"), lib_common.NodeLiteral( attr_notifref ) ) )

			#attr_cronref = elt_app.getAttributeNode('cronref').value
			#grph.add( ( appNode, lib_common.MakeProp("Cronref"), lib_common.NodeLiteral( attr_cronref ) ) )

			#appParent = None
			#appChildren = []

			for elt_component in elt_app.getElementsByTagName('component'):
				attr_component_name = elt_component.getAttributeNode('name').value

				sys.stderr.write("attr_component_name=%s\n"%attr_component_name)

				if attr_component_name == ac2Comp:
					attr_component_description = elt_component.getAttributeNode('description')
					if attr_component_description:
						grph.add( ( compNode, pc.property_information, lib_common.NodeLiteral( attr_component_description.value ) ) )

					attr_component_group = elt_component.getAttributeNode('group')
					if attr_component_group:
						grph.add( ( compNode, lib_common.MakeProp("Group"), lib_common.NodeLiteral( attr_component_group.value ) ) )

					attr_component_type = elt_component.getAttributeNode('type')
					if attr_component_type:
						grph.add( ( compNode, lib_common.MakeProp("Type"), lib_common.NodeLiteral( attr_component_type.value ) ) )

					nodeFather = None
					for elt_father in elt_component.getElementsByTagName('father'):
						# There should be one parent only.
						attr_father_name = elt_father.firstChild.nodeValue
						sys.stderr.write("attr_father_name=%s\n"%attr_father_name)
						nodeFather = ComponentNameToNode(ac2File,attr_app_name,attr_father_name)

						grph.add( ( nodeFather, AC2.propParent, compNode ) )
						grph.add( ( appNode, AC2.propComp2App, nodeFather ) )

					if not nodeFather:
						grph.add( ( appNode, AC2.propComp2App, compNode ) )
				else:
					currCompNode = ComponentNameToNode(ac2File,attr_app_name,attr_component_name)
					for elt_father in elt_component.getElementsByTagName('father'):
						# There should be one parent only.
						attr_father_name = elt_father.firstChild.nodeValue

						if attr_father_name == ac2Comp:
							sys.stderr.write("ac2Comp attr_father_name=%s\n"%attr_father_name)
							nodeChild = ComponentNameToNode(ac2File,attr_app_name,attr_father_name)

							grph.add( ( compNode, AC2.propParent, currCompNode ) )
	return



def Main():

	cgiEnv = lib_common.CgiEnv()

	ac2File = cgiEnv.m_entity_id_dict["File"]
	ac2App = cgiEnv.m_entity_id_dict["App"]
	ac2Comp = cgiEnv.m_entity_id_dict["Comp"]

	sys.stderr.write("ac2File=%s ac2App=%s ac2Comp=%s\n"% (ac2File,ac2App,ac2Comp) )

	grph = cgiEnv.GetGraph()

	DisplayComponentDependencies(grph,ac2File,ac2App,ac2Comp)

	cgiEnv.OutCgiRdf( "LAYOUT_RECT", [AC2.propParent] )

if __name__ == '__main__':
	Main()
