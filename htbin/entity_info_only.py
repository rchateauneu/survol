#!/usr/bin/python

"""
Overview
"""

import os
import re
import sys
import psutil
import rdflib
import lib_util
import lib_common
from lib_properties import pc

# This displays only data nodes about the object, not the script.
# It is used by entity.py and also by the D3 interface with the CGI parameter mode=json,
# because this interface does not need the hierarchy of scripts.

################################################################################

#Un module est defini par son ontologie:
#Quand on itere sur des directories et sous-directories pour en afficher les scripts,
#il suffit de s'assurer que chaque sous-module a la meme ontologie que le point de depart
#(On bien n a pas d ontologie, bref, que ce soit coherent avec le point de depart.)
# De meme dans sources_top: On devrait aller chercher dans scripts_types,
# les scripts qui n ont pas d'ontologie.
# Dans entity.py, comme on a une entite (la machine courante),
# on peut aller chercher les scripts qui ont une ontologie pour ces classes.

# On prend l ontologie du niveau courant ou on se trouve,
# donne par la entity_class.
# Si y en a pas (sources_top) et ben y en a pas.
# Ensuite on liste recursivement les fichiers mais des que l ontologie change,
# c est a dire, si une ontologie est definie dans un module intermediaire.
# (Ce qu on voit en chargeant le module implicitement) alors on laisse tomber)

# En plus, dans le entity par defaut, comme on a forcement un user et une machine,
# on va chercher les scripts de ces deux entites.

# Probleme: On doit aller chercher toutes les entites, charger tous les modules.

################################################################################

def AddInformation(grph,rootNode,entity_id, entity_type):
	entity_ids_arr = lib_util.EntityIdToArray( entity_type, entity_id )

	# Each entity type ("process","file" etc... ) can have a small library
	# of its own, for displaying a rdf node of this type.
	if entity_type:
		entity_module = lib_util.GetEntityModule(entity_type)
		if entity_module:
			try:
				entity_module.AddInfo( grph, rootNode, entity_ids_arr )
			except AttributeError:
				exc = sys.exc_info()[1]
				sys.stderr.write("No AddInfo for %s %s: %s\n"%( entity_type, entity_id, str(exc) ))
	else:
		sys.stderr.write("No lib_entities for %s %s\n"%( entity_type, entity_id ))

def Main():
	# This can process remote hosts because it does not call any script, just shows them.
	cgiEnv = lib_common.CgiEnv(
					can_process_remote = True)
	entity_id = cgiEnv.m_entity_id
	entity_host = cgiEnv.GetHost()

	( nameSpace, entity_type, entity_namespace_type ) = cgiEnv.GetNamespaceType()

	grph = rdflib.Graph()

	rootNode = lib_util.RootUri()

	if entity_id != "" or entity_type == "":
		AddInformation(grph,rootNode,entity_id, entity_type )

	cgiEnv.OutCgiRdf(grph, "LAYOUT_RECT", [pc.property_directory,pc.property_rdf_data1])

if __name__ == '__main__':
	Main()

