#!/usr/bin/python

"""
Displays data sources for a class
"""

import sys
import os
import rdflib
import lib_util
import lib_common
import lib_wbem
import lib_wmi
from lib_properties import pc

# This can process remote hosts because it calls scripts which can access remote data. I hope.
cgiEnv = lib_common.CgiEnv("Generalised class", can_process_remote = True)

# entity_type = cgiEnv.m_entity_type
( nameSpace, className, entity_type ) = cgiEnv.GetNamespaceType()

entity_host = cgiEnv.GetHost()
entity_id = cgiEnv.m_entity_id

# QUERY_STRING=xid=http%3A%2F%2F192.168.1.88%3A5988%2Froot%2FPG_Internal%3APG_WBEMSLPTemplate
sys.stderr.write("class_type_all entity_host=%s entity_id=%s\n" % ( entity_host, entity_id ) )

grph = rdflib.Graph()

# TODO: Utiliser la bonne fonction !!!
rootNode = lib_util.RootUri()

# La, je ne sais pas trop bien quel URL mettre. S'agit-il d'une class CIM ?
# Mais en principe on veut qu'elles soient homogenes.
if nameSpace != "" and entity_host != "":
	namespaceUrl = lib_wbem.NamespaceUrl(nameSpace,entity_host)
	namespaceNode = rdflib.term.URIRef( namespaceUrl )
	grph.add( ( rootNode, pc.property_rdf_data_nolist, namespaceNode ) )

objtypeNode = rdflib.term.URIRef( lib_util.uriRoot + '/objtypes.py' )
grph.add( ( rootNode, pc.property_rdf_data_nolist, objtypeNode ) )

# This try to find a correct url for an entity type, without an entity id.
# TODO: Donner plusieurs types d'enumerations possibles
try:
	baseFilNam = "/sources_top/enumerate." + className + ".py"
	# WHY IS IT UNUSED?
	indexFilNam = lib_util.gblTopScripts + baseFilNam
	info = os.stat(indexFilNam)
	localClassUrl = lib_util.ScriptizeCimom( baseFilNam, className, "", entity_host )
except Exception:
	# If there is no script to enumerate all objects of a given type.
	# exc = sys.exc_info()[1]
	# Sinon, entity.py devra gerer le probleme.
	localClassUrl = lib_util.ScriptizeCimom( baseFilNam, entity_type, "", entity_host )

localClassNode =  rdflib.term.URIRef( localClassUrl )
grph.add( ( rootNode, lib_common.pc.property_directory, localClassNode ) )

# Maybe some of these servers are not able to display anything about this object.
wbem_servers_desc_list = lib_wbem.GetWbemUrls( entity_host, nameSpace, className, entity_id )
for url_server in wbem_servers_desc_list:
	wbemNode = rdflib.term.URIRef(url_server[0])
	grph.add( ( rootNode, pc.property_wbem_data, wbemNode ) )
	# EntHostToIp
	# wbemHostNode = lib_common.gUriGen.HostnameUri( "url_server" )

	# Representation de cette classe dans WBEM.
	# TODO: AJOUTER LIEN VERS L EDITEUR DE CLASSE, PAS SEULEMENT LE SERVEUR WBEM.

	wbemHostNode = lib_common.gUriGen.HostnameUri( url_server[1] )
	grph.add( ( wbemNode, pc.property_host, wbemHostNode ) )
	# TODO: Yawn server ??
	grph.add( ( wbemNode, pc.property_wbem_server, rdflib.Literal( url_server[1] ) ) )

wmiurl = lib_wmi.GetWmiUrl( entity_host, nameSpace, entity_type, entity_id )
if not wmiurl is None:
	sys.stderr.write("entity_host=%s nameSpace=%s entity_type=%s className=%s wmiurl=%s\n" % ( entity_host, nameSpace, entity_type, className, str(wmiurl) ) )
	wmiNode = rdflib.term.URIRef(wmiurl)
	grph.add( ( rootNode, pc.property_wmi_data, wmiNode ) )

	wmiClassUrl = lib_wmi.ClassUrl(nameSpace,entity_host,className)
	sys.stderr.write("wmiClassUrl=%s\n" % str(wmiClassUrl) )
	wmiClassNode = rdflib.term.URIRef( wmiClassUrl )
	grph.add( ( wmiNode, rdflib.Literal("Class edition"), wmiClassNode ) )




cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT")


