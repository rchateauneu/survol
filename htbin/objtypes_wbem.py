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

cgiEnv = lib_common.CgiEnv("WBEM classes in namespace", can_process_remote = True)

( wbemNamespace, entity_type, entity_namespace_type ) = cgiEnv.GetNamespaceType()

sys.stderr.write("wbemNamespace=%s entity_type=%s entity_namespace_type=%s\n" % (wbemNamespace, entity_type,entity_namespace_type))

# Should be empty.
entity_id = cgiEnv.GetId()
if entity_id != "":
	pass

cimomUrl = cgiEnv.GetHost()

if str(wbemNamespace) == "":
	lib_common.ErrorMessageHtml("namespace should not be empty. entity_namespace_type="+entity_namespace_type)

grph = rdflib.Graph()

connWbem = lib_wbem.WbemConnection(cimomUrl)
wbemUrl = lib_wbem.NamespaceUrl( wbemNamespace, cimomUrl )
rootNode = rdflib.term.URIRef( wbemUrl )

sys.stderr.write("cimomUrl=%s\n" % cimomUrl)

# topclassNam is None at first call.
def PrintClassRecu(grph, rootNode, tree_classes, topclassNam):

	# Unique script for all data source.
	# sys.stderr.write("PrintClassRecu topclassNam=%s\n" % str(topclassNam) )
	wbemNode = lib_util.EntityClassNode( topclassNam, wbemNamespace, cimomUrl, "WBEM" )

	grph.add( ( rootNode, pc.property_cim_subclass, wbemNode ) )

	try:
		for cl in tree_classes[topclassNam]:
			clnam = cl.classname
			PrintClassRecu(grph, wbemNode, tree_classes, clnam)
	except KeyError:
		pass # No subclass.

try:
	treeClassesFiltered = lib_wbem.GetClassesTreeInstrumented(connWbem,wbemNamespace)
except Exception:
	exc = sys.exc_info()[1]
	lib_common.ErrorMessageHtml("Instrumented classes: url="+cimomUrl+" ns="+wbemNamespace+" entity_id="+entity_id+" Caught:"+str(exc))


PrintClassRecu(grph, rootNode, treeClassesFiltered, None)

cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT",[pc.property_cim_subclass])
# cgiEnv.OutCgiRdf(grph)

