#!/usr/bin/python

"""
Generalised class: Displays data sources for a class
"""

import os
import six
import sys
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
cgiEnv = lib_common.CgiEnv(can_process_remote = True)

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

objtypeNode = rdflib.term.URIRef( lib_util.uriRoot + '/objtypes.py' )
grph.add( ( rootNode, pc.property_rdf_data_nolist2, objtypeNode ) )

# Now, adds the base classes of this one, at least one one level.
def WbemAddBaseClass(grph,connWbem,wbemNode,entity_host, wbemNamespace, entity_type):
	wbemKlass = lib_wbem.WbemGetClassObj(connWbem,entity_type,wbemNamespace)
	if not wbemKlass:
		return ( None, None )

	superKlassName = wbemKlass.superclass

	# sys.stderr.write("WBEM superKlassName=%s\n" % superKlassName)
	# An empty string or None.
	if not superKlassName:
		return ( None, None )

	# TODO: Should be changed, this is slow and inconvenient.
	wbemSuperUrlsList = lib_wbem.GetWbemUrls( entity_host, wbemNamespace, superKlassName, "" )
	if not wbemSuperUrlsList:
		return ( None, None )

	# TODO: Which one should we take, http or https ???
	wbemSuperUrl = wbemSuperUrlsList[0][0]
	sys.stderr.write("WBEM wbemSuperUrl=%s\n" % wbemSuperUrl)

	wbemSuperNode = rdflib.term.URIRef(wbemSuperUrl)

	grph.add( ( wbemSuperNode, pc.property_cim_subclass, wbemNode ) )
	klaDescrip = lib_wbem.WbemClassDescription(connWbem,superKlassName,wbemNamespace)
	if not klaDescrip:
		klaDescrip = "Undefined class %s %s" % ( wbemNamespace, superKlassName )
	grph.add( ( wbemSuperNode, pc.property_information, rdflib.Literal(klaDescrip ) ) )

	return ( wbemSuperNode, superKlassName )

# Adds the list of base classes. Returns the list of pairs (name node),
# so it can be matched againt another inheritance tree.
def WbemAddBaseClasses(grph,connWbem,wbemNode,entity_host, wbemNamespace, entity_type):
	pairNameNode = dict()
	while wbemNode:
		( wbemSuperNode, superClass ) = WbemAddBaseClass(grph,connWbem,wbemNode,entity_host, wbemNamespace, entity_type)
		pairNameNode[entity_type] = wbemNode
		wbemNode = wbemSuperNode
		entity_type = superClass
	return pairNameNode

def CreateWbemNode(grph,rootNode,entity_host, nameSpace, className, entity_id):
	wbemNamespace = nameSpace.replace("\\","/")
	wbem_servers_desc_list = lib_wbem.GetWbemUrls( entity_host, wbemNamespace, className, entity_id )
	for url_server in wbem_servers_desc_list:
		wbemNode = rdflib.term.URIRef(url_server[0])
		grph.add( ( rootNode, pc.property_wbem_data, wbemNode ) )

		# Le naming est idiot: "rchateau-HP at localhost"
		wbemHostNode = lib_common.gUriGen.HostnameUri( url_server[1] )
		grph.add( ( wbemNode, pc.property_host, wbemHostNode ) )

		# TODO: Add a Yawn server ??
		grph.add( ( wbemNode, pc.property_wbem_server, rdflib.Literal( url_server[1] ) ) )

		# Now adds the description of the class.
		connWbem = lib_wbem.WbemConnection(entity_host)
		klaDescrip = lib_wbem.WbemClassDescription(connWbem,className,wbemNamespace)
		okWbemClass = True
		if not klaDescrip:
			okWbemClass = False
			klaDescrip = "Undefined class %s %s" % ( wbemNamespace, className )
		grph.add( ( wbemNode, pc.property_information, rdflib.Literal(klaDescrip) ) )

		# Maybe this class is not Known in WBEM.
		try:
			pairNameNode = WbemAddBaseClasses(grph,connWbem,wbemNode,entity_host, nameSpace, className)
		except:
			pairNameNode = None

		if okWbemClass and wbemOk and nameSpace != "" and entity_host != "":
			namespaceUrl = lib_wbem.NamespaceUrl(nameSpace,entity_host,className)
			namespaceNode = rdflib.term.URIRef( namespaceUrl )
			grph.add( ( wbemNode, pc.property_information, namespaceNode ) )

	# TODO: This is a bit absurd because we return just one list.
	return pairNameNode

# Adds a WMI node and other stuff, for the class name.
def CreateWmiNode(grph,rootNode,entity_host, nameSpace, className, entity_id):
	wmiurl = lib_wmi.GetWmiUrl( entity_host, nameSpace, className, entity_id )
	if wmiurl is None:
		return

	# There might be "http:" or the port number around the host.
	# hostOnly = lib_util.EntHostToIp(entity_host)
	# sys.stderr.write("entity_host=%s nameSpace=%s entity_type=%s className=%s wmiurl=%s\n" % ( entity_host, nameSpace, entity_type, className, str(wmiurl) ) )
	wmiNode = rdflib.term.URIRef(wmiurl)
	grph.add( ( rootNode, pc.property_wmi_data, wmiNode ) )

	# TODO: Shame, we just did it in GetWmiUrl.
	ipOnly = lib_util.EntHostToIp(entity_host)
	try:
		connWmi = lib_wmi.WmiConnect(ipOnly,nameSpace)
		lib_wmi.WmiAddClassQualifiers( grph, connWmi, wmiNode, className, False )

		# Now displays the base classes, to the top of the inheritance tree.
		pairNameNode = lib_wmi.WmiAddBaseClasses(grph,connWmi,wmiNode,ipOnly, nameSpace, className)

	except Exception:
		pairNameNode = None
		# TODO: If the class is not defined, maybe do not display it.
		exc = sys.exc_info()[1]
		grph.add( ( wmiNode, lib_common.MakeProp("WMI Error"), rdflib.Literal(str(exc)) ) )

	urlNameSpace = lib_wmi.NamespaceUrl(nameSpace,ipOnly,className)
	# sys.stderr.write("entity_host=%s urlNameSpace=%s\n"%(entity_host,urlNameSpace))
	grph.add( ( wmiNode, pc.property_information, rdflib.term.URIRef(urlNameSpace) ) )

	return pairNameNode

#On rajoute aussi les subclasses wbem: objtypes_wbem.
#Et aussi la classe de base de wmi et wbem, et encore mieux: les deux class_type_all de ces classes de base.
#Bien entendu ca va fusionner si ce sont les memes.
#On peut meme afficher sur plusieurs niveaux: Meme boucle que dans les objets:
#Comme ca on aura le chainage.
#On met la profindeur en parametre

# entity_type = "CIM_Process", "Win32_Service" etc...
# This might happen at an intermediary level, with inheritance (To be implemented).
def AddCIMClasses(grph,rootNode,entity_host, nameSpace, className, entity_id):
	# Maybe some of these servers are not able to display anything about this object.

	pairNameNodeWbem = None
	if wbemOk:
		if lib_wbem.ValidClassWbem(entity_host, className):
			pairNameNodeWbem = CreateWbemNode(grph,rootNode,entity_host, nameSpace, className, entity_id)

	pairNameNodeWmi = None
	if lib_wmi.ValidClassWmi(entity_host, className):
		pairNameNodeWmi = CreateWmiNode(grph,rootNode,entity_host, nameSpace, className, entity_id)

	# Match the two inheritance trees.
	if pairNameNodeWbem and pairNameNodeWmi:
		for ( baseClsNam, nodeWbem ) in six.iteritems( pairNameNodeWbem ):
			try:
				nodeWmi = pairNameNodeWmi[baseClsNam]
			except KeyError:
				continue

			nodeClsAll = lib_util.EntityClassNode( baseClsNam, nameSpace, entity_host, "WBEM ou WMI" )
			grph.add( ( nodeClsAll, pc.property_wbem_data, nodeWbem))
			grph.add( ( nodeClsAll, pc.property_wmi_data, nodeWmi))

def CreateOurNode(grph,rootNode,entity_host, nameSpace, className, entity_id):
	# This try to find a correct url for an entity type, without an entity id.
	# TODO: Donner plusieurs types d'enumerations possibles.
	# At the moment, we just expect a file called "enumerate_<entity>.py"
	enumerateScript = "enumerate_" + className + ".py"
	# sys.stderr.write("enumerateScript=%s\n" % enumerateScript)
	baseDir = lib_util.gblTopScripts + "/sources_top"

	# TODO: Parser en fonction des "/"

	# TODO: C est idiot: Pourquoi boucler alors qu on connait le nom du fichier ??

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



CreateOurNode(grph,rootNode,entity_host, nameSpace, className, entity_id)

# Do this for each intermediary entity type (Between slashes).
AddCIMClasses(grph,rootNode,entity_host, nameSpace, className, entity_id)

cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT_TB")


