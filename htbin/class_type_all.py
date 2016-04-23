#!/usr/bin/python

"""
Displays data sources for a class
"""

import sys
import os
import rdflib
import lib_util
import lib_common
try:
	import lib_wbem
	wbemOk = True
except ImportError:
	wbemOk = False
import lib_wmi
from lib_properties import pc

# This can process remote hosts because it calls scripts which can access remote data. I hope.
cgiEnv = lib_common.CgiEnv("Generalised class", can_process_remote = True)

# entity_type = cgiEnv.m_entity_type
( nameSpace, className, entity_type ) = cgiEnv.GetNamespaceType()

# Just in case ...
if nameSpace == "/":
	nameSpace = ""

entity_host = cgiEnv.GetHost()
entity_id = cgiEnv.m_entity_id

# QUERY_STRING=xid=http%3A%2F%2F192.168.1.88%3A5988%2Froot%2FPG_Internal%3APG_WBEMSLPTemplate
sys.stderr.write("class_type_all entity_host=%s entity_id=%s\n" % ( entity_host, entity_id ) )

grph = rdflib.Graph()

# TODO: Utiliser la bonne fonction !!!
rootNode = lib_util.RootUri()

# La, je ne sais pas trop bien quel URL mettre. S'agit-il d'une class CIM ?
# Mais en principe on veut qu'elles soient homogenes.
if wbemOk and nameSpace != "" and entity_host != "":
	namespaceUrl = lib_wbem.NamespaceUrl(nameSpace,entity_host)
	namespaceNode = rdflib.term.URIRef( namespaceUrl )
	grph.add( ( rootNode, pc.property_rdf_data_nolist, namespaceNode ) )

objtypeNode = rdflib.term.URIRef( lib_util.uriRoot + '/objtypes.py' )
grph.add( ( rootNode, pc.property_rdf_data_nolist, objtypeNode ) )

# This try to find a correct url for an entity type, without an entity id.
# TODO: Donner plusieurs types d'enumerations possibles.
# At the moment, we just expect a file called "enumerate.<entity>.py"
enumerateScript = "enumerate_" + className + ".py"
# sys.stderr.write("enumerateScript=%s\n" % enumerateScript)
baseDir = lib_util.gblTopScripts + "/sources_top"
for dirpath, dirnames, filenames in os.walk( baseDir ):
	# sys.stderr.write("dirpath=%s\n" % dirpath)
	for filename in [f for f in filenames if f == enumerateScript ]:

		shortDir = dirpath[ len(lib_util.gblTopScripts) : ]
		fullScriptNam = os.path.join(shortDir, filename).replace('\\','/')
		sys.stderr.write("fullScriptNam=%s\n" % fullScriptNam)

		# TODO: Maybe remove the beginning of the file.
		localClassUrl = lib_util.ScriptizeCimom( fullScriptNam, className, entity_host )

		localClassNode =  rdflib.term.URIRef( localClassUrl )
		grph.add( ( rootNode, lib_common.pc.property_directory, localClassNode ) )

# Maybe some of these servers are not able to display anything about this object.
if wbemOk:
	wbemNamespace = nameSpace.replace("\\","/")
	wbem_servers_desc_list = lib_wbem.GetWbemUrls( entity_host, wbemNamespace, className, entity_id )
	for url_server in wbem_servers_desc_list:
		wbemNode = rdflib.term.URIRef(url_server[0])
		grph.add( ( rootNode, pc.property_wbem_data, wbemNode ) )

		# Representation de cette classe dans WBEM.
		# TODO: AJOUTER LIEN VERS L EDITEUR DE CLASSE, PAS SEULEMENT LE SERVEUR WBEM.

		wbemHostNode = lib_common.gUriGen.HostnameUri( url_server[1] )
		grph.add( ( wbemNode, pc.property_host, wbemHostNode ) )
		# TODO: Yawn server ??
		grph.add( ( wbemNode, pc.property_wbem_server, rdflib.Literal( url_server[1] ) ) )

		# Now adds the description of the class.
		connWbem = lib_wbem.WbemConnection(entity_host)
		klaDescrip = lib_wbem.WbemClassDescription(connWbem,className,wbemNamespace)
		grph.add( ( wbemNode, pc.property_information, rdflib.Literal(klaDescrip ) ) )

wmiurl = lib_wmi.GetWmiUrl( entity_host, nameSpace, className, entity_id )
if not wmiurl is None:
	# There might be "http:" or the port number around the host.
	# hostOnly = lib_util.EntHostToIp(entity_host)
	# sys.stderr.write("entity_host=%s nameSpace=%s entity_type=%s className=%s wmiurl=%s\n" % ( entity_host, nameSpace, entity_type, className, str(wmiurl) ) )
	wmiNode = rdflib.term.URIRef(wmiurl)
	grph.add( ( rootNode, pc.property_wmi_data, wmiNode ) )

	try:
		# TODO: Shame, we just did it in GetWmiUrl.
		ipOnly = lib_util.EntHostToIp(entity_host)
		connWmi = lib_wmi.WmiConnect(ipOnly,nameSpace)
		lib_wmi.WmiAddClassQualifiers( grph, connWmi, wmiNode, className, False )
	except Exception:
		# TODO: If the class is not defined, maybe do not display it.
		exc = sys.exc_info()[1]
		grph.add( ( wmiNode, lib_common.MakeProp("WMI Error"), rdflib.Literal(str(exc)) ) )



	#wmiClassUrl = lib_wmi.ClassUrl(nameSpace,hostOnly,className)
	#sys.stderr.write("wmiClassUrl=%s\n" % str(wmiClassUrl) )
	#wmiClassNode = rdflib.term.URIRef( wmiClassUrl )
	#grph.add( ( wmiNode, lib_common.MakeProp("Class_edition"), wmiClassNode ) )

cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT")


