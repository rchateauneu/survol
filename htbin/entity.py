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

# This script is also used as a module.
import entity_dirmenu_only # Also used with the CGI parameter mode=menu


##### import entity_info_only # Also used with the CGI parameter mode=json
## WE SHOULD NOT LOAD USELESS STUFF WHEN WE WANT TO DISPLAY ONLY THE NODES IN THE D3 INTERFACE.
## AND THE LINKS LIKE WBEM OR WMI SHOULD BE PROPERLY DISPLAYED.
## IN THE CONTEXTUAL MENU ??

from sources_types import CIM_Process
from sources_types import CIM_ComputerSystem

################################################################################

# WHAT TO DO WITH THE HOST ???????
# This should not be the same scripts:
# Some "normal" scripts are able to use a hostname, but this is very rare.
# CgiEnv is able to say that. Also, this must be stored in the info cache.
# If we take the entity_id from CgiEnv without explicitely saying
# that the current script can process the hostname, then it is an error.
# Also: This is where we need to "talk" to the other host ?
# And we must display the node of the host as seen from the local machine.



################################################################################

def CurrentUser():
	currProc = psutil.Process(os.getpid())
	return CIM_Process.PsutilProcToUser(currProc)

def AddDefaultNodes(grph,rootNode,entity_host):
	currentNodeHostname = lib_common.gUriGen.HostnameUri( lib_util.currentHostname )
	grph.add( ( currentNodeHostname, pc.property_information, rdflib.Literal("Current host:"+lib_util.currentHostname) ) )
	grph.add( ( rootNode, pc.property_rdf_data_nolist2, currentNodeHostname ) )

	currUsername = CurrentUser()
	currentNodeUser = lib_common.gUriGen.UserUri( currUsername )
	grph.add( ( currentNodeUser, pc.property_information, rdflib.Literal("Current user:"+currUsername) ) )
	grph.add( ( rootNode, pc.property_rdf_data_nolist2, currentNodeUser ) )

# TODO: Maybe the property should be property_script ??
def AddDefaultScripts(grph,rootNode,entity_host):
	nodeObjTypes = rdflib.term.URIRef( lib_util.uriRoot + '/objtypes.py' )
	grph.add( ( rootNode, pc.property_rdf_data_nolist2, nodeObjTypes ) )

	# Gives a general access to WBEM servers. In fact we might iterate on several servers, or none.
	nodePortalWbem = lib_util.UrlPortalWbem(entity_host)
	grph.add( ( rootNode, pc.property_rdf_data_nolist2, nodePortalWbem ) )

	# Gives a general access to WMI servers.
	nodePortalWmi = lib_util.UrlPortalWmi(entity_host)
	grph.add( ( rootNode, pc.property_rdf_data_nolist2, nodePortalWmi ) )


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

def Main():

	paramkeyShowAll = "Show all scripts"

	# This can process remote hosts because it does not call any script, just shows them.
	cgiEnv = lib_common.CgiEnv(
					can_process_remote = True,
					parameters = { paramkeyShowAll : False })
	entity_id = cgiEnv.m_entity_id
	entity_host = cgiEnv.GetHost()
	flagShowAll = int(cgiEnv.GetParameters( paramkeyShowAll ))

	( nameSpace, entity_type, entity_namespace_type ) = cgiEnv.GetNamespaceType()

	is_host_remote = not lib_util.IsLocalAddress( entity_host )

	sys.stderr.write("entity: entity_host=%s entity_type=%s entity_id=%s is_host_remote=%r\n" % ( entity_host, entity_type, entity_id, is_host_remote ) )

	# It is simpler to have an empty entity_host, if possible.
	# CHAIS PAS. EN FAIT C EST LE CONTRAIRE, IL FAUT METTRE LE HOST
	if not is_host_remote:
		entity_host = ""

	grph = cgiEnv.GetGraph()

	rootNode = lib_util.RootUri()

	entity_ids_arr = lib_util.EntityIdToArray( entity_type, entity_id )
	# entity_info_only.AddInformation(grph,rootNode,entity_id, entity_type)

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

	# When displaying in json mode, the scripts are shown with a contextual menu, not with D3 modes..
	if lib_common.GuessDisplayMode() != "json":
		entity_dirmenu_only.DirToMenu(grph,rootNode,entity_type,entity_id,is_host_remote,flagShowAll)

		if entity_type != "":
			sys.stderr.write("Entering AddWbemWmiServers")
			CIM_ComputerSystem.AddWbemWmiServers(grph,rootNode, entity_host, nameSpace, entity_type, entity_id)

		AddDefaultScripts(grph,rootNode,entity_host)

	AddDefaultNodes(grph,rootNode,entity_host)

	cgiEnv.OutCgiRdf( "LAYOUT_RECT", [pc.property_directory,pc.property_script])

if __name__ == '__main__':
	Main()

