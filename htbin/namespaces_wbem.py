#!/usr/bin/python

"""
WBEM namespaces
"""

import sys
import lib_util
import lib_wbem
import lib_common
import rdflib
from lib_properties import pc

def Main():
	cgiEnv = lib_common.CgiEnv(can_process_remote = True)

	cimomUrl = cgiEnv.GetHost()

	grph = cgiEnv.GetGraph()

	# There is no consensus on the WBEM class for namespaces,
	# so we have ours which must be correctly mapped.
	namespace_class = "wbem_namespace"
	rootNode = lib_util.EntityUri(namespace_class,"")

	connWbem = lib_wbem.WbemConnection(cimomUrl)

	try:
		nsd = lib_wbem.EnumNamespacesCapabilities(connWbem)
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Namespaces from :"+cimomUrl+" Caught:"+str(exc))

	# TODO: We should draw a namespaces tree but more examples needed.
	for nskey in nsd:

		cnt = nsd[nskey]
		# Special case because it is not displayed like a normal entity.
		# Oui mais ca marche aussi avec wmi ?
		# Pourrait-on combiner namespace+classe ? entity_type="root/cim_v2/CIM_Process" ?
		# Si l'entity_type termine par un slash, donc c'est un namespace ?
		# Ca nous permettrait de creer des namespaces dans notre ontologie,
		# par exemple pour Oracle. Ce serait simplement un directory.
		# ATTENTION: Avoir la liste de nos entity_types sera moins immediat.
		wbemUrl = lib_wbem.NamespaceUrl( nskey, cimomUrl )
		wbemNode = rdflib.term.URIRef( wbemUrl )

		grph.add( ( rootNode, pc.property_cim_subnamespace, wbemNode ) )
		grph.add( ( wbemNode, pc.property_information, rdflib.Literal(nskey) ) )
		grph.add( ( wbemNode, pc.property_information, rdflib.Literal(cnt) ) )

	cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT")

if __name__ == '__main__':
	Main()
