#!/usr/bin/python

"""
WBEM classes of a given namespace
"""

import sys
import lib_util
import lib_wbem
import lib_common
import rdflib
from lib_properties import pc

paramkeyMaxDepth = "Maximum depth"

# TODO: The type should really be an integer.
cgiEnv = lib_common.CgiEnv("WBEM classes in namespace",
				can_process_remote = True,
				parameters = { paramkeyMaxDepth : "1" })

( wbemNamespace, entity_type, entity_namespace_type ) = cgiEnv.GetNamespaceType()

maxDepth = int(cgiEnv.GetParameters( paramkeyMaxDepth ))

sys.stderr.write("wbemNamespace=%s entity_type=%s entity_namespace_type=%s maxDepth=%d\n" % (wbemNamespace, entity_type,entity_namespace_type,maxDepth))

cimomUrl = cgiEnv.GetHost()

if str(wbemNamespace) == "":
	lib_common.ErrorMessageHtml("namespace should not be empty. entity_namespace_type="+entity_namespace_type)

grph = rdflib.Graph()

connWbem = lib_wbem.WbemConnection(cimomUrl)

def WbemNamespaceNode( clsNam ):
	wmiUrl = lib_wbem.NamespaceUrl( wbemNamespace, cimomUrl, clsNam )
	return rdflib.term.URIRef( wmiUrl )

# entity_type might an empty string.
rootNode = WbemNamespaceNode(entity_type)


sys.stderr.write("cimomUrl=%s entity_type=%s\n" % (cimomUrl,entity_type) )

# topclassNam is None at first call.
def PrintClassRecu(grph, rootNode, tree_classes, topclassNam, depth):
	# sys.stderr.write("topclassNam=%s depth=%d\n" % (topclassNam,depth))

	if depth > maxDepth	:
		return
	depth += 1

	# Unique script for all data source.
	# sys.stderr.write("PrintClassRecu topclassNam=%s\n" % str(topclassNam) )
	wbemNode = lib_util.EntityClassNode( topclassNam, wbemNamespace, cimomUrl, "WBEM" )
	grph.add( ( rootNode, pc.property_cim_subclass, wbemNode ) )

	# The class is the starting point when displaying the class tree of the namespace.
	wbemNodeSub = WbemNamespaceNode(topclassNam)
	grph.add( ( wbemNode, pc.property_rdf_data_nolist, rdflib.Literal(wbemNodeSub) ) )


	# TODO: AJOUTER LE LIEN YAWN. Il y a de fortes chances pour que Yawn soit installe.
	# http://192.168.1.88/yawn/GetClass/TUT_UnixProcess?url=http%3A%2F%2F192.168.1.88&verify=0&ns=root%2Fcimv2
	# http://rchateau-hp.home/yawn/GetClass/PG_UnixProcess?url=http://192.168.1.88:5988?verify=0$ns=root/cimv2
	# TODO: REPARER CECI
	# yawnUrl = "http://%s/yawn/GetClass/%s?url=%s?verify=0$ns=%s" % (lib_util.currentHostname,topclassNam,cimomUrl,wbemNamespace)

	# We could take lib_util.currentHostname but Yawn is more probably running on a machine where Pegasus is there.
	cimomNoPort = cimomUrl.split(":")[1]
	# yawnUrl = "http://%s/yawn/GetClass/%s?url=%s&verify=0&ns=%s" % (cimomNoPort,topclassNam,cimomUrl,wbemNamespace)
	# yawnUrl = lib_util.EncodeUri(yawnUrl)
	yawnUrl = "%s/yawn/GetClass/%s?url=%s&verify=0&ns=%s" % (cimomNoPort,topclassNam,cimomUrl,wbemNamespace)
	# TODO: SVG prefixe l'URL qui devient inutilisable.
	yawnUrl = "http://" + lib_util.EncodeUri(yawnUrl)
	# yawnUrl = lib_util.EncodeUri(yawnUrl)
	grph.add( ( wbemNode, pc.property_html_data, rdflib.term.URIRef(yawnUrl) ) )

	try:
		# TODO: This should be indexed with a en empty string !
		if topclassNam == "":
			topclassNam = None
		for cl in tree_classes[topclassNam]:
			PrintClassRecu(grph, wbemNode, tree_classes, cl.classname, depth)
	except KeyError:
		pass # No subclass.

treeClassesFiltered = lib_wbem.GetClassesTreeInstrumented(connWbem,wbemNamespace)

# PrintClassRecu(grph, rootNode, treeClassesFiltered, None, 0)
PrintClassRecu(grph, rootNode, treeClassesFiltered, entity_type, 0)

sys.stderr.write("entity_type=%s\n" % entity_type)

# If we are not at the top of the tree:
if entity_type != "":
	# Now, adds the base classes of this one, at least one one level.
	wbemKlass = lib_wbem.WbemGetClassObj(connWbem,entity_type,wbemNamespace)

	superKlassName = wbemKlass.superclass

	sys.stderr.write("superKlassName=%s\n" % superKlassName)
	# An empty string or None.
	if superKlassName:
		wbemSuperNode = WbemNamespaceNode( superKlassName )
		grph.add( ( wbemSuperNode, pc.property_cim_subclass, rootNode ) )
		klaDescrip = lib_wbem.WbemClassDescription(connWbem,superKlassName,wbemNamespace)
		grph.add( ( wbemSuperNode, pc.property_information, rdflib.Literal(klaDescrip ) ) )

cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT",[pc.property_cim_subclass])
# cgiEnv.OutCgiRdf(grph)

