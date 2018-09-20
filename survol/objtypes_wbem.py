#!/usr/bin/python

"""
WBEM classes in namespace
"""

import sys
import lib_util
import lib_wbem
import lib_common
from lib_properties import pc

def WbemNamespaceNode( wbemNamespace, cimomUrl, clsNam ):
	wbemUrl = lib_wbem.NamespaceUrl( wbemNamespace, cimomUrl, clsNam )
	return lib_common.NodeUrl( wbemUrl )

# http://pywbem.github.io/yawn/index.html
# "YAWN stands for "Yet Another WBEM Navigator"
# and provides a way to access WBEM servers and to navigate between the CIM objects returned."
# https://github.com/pywbem/yawn
# TODO: Should check if "Yawn" is running on the target machine.
def AddYawnNode(cimomUrl,topclassNam,wbemNamespace,grph,wbemNode):
	# We could take lib_util.currentHostname but Yawn is more probably running on a machine where Pegasus is there.
	cimomNoPort = cimomUrl.split(":")[1]

	# The character "&" must be escaped TWICE ! ...
	yawnUrl = "http:%s/yawn/GetClass/%s?url=%s&amp;amp;verify=0&amp;amp;ns=%s" % (cimomNoPort,topclassNam,lib_util.EncodeUri(cimomUrl),lib_util.EncodeUri(wbemNamespace))

	# "http://192.168.1.88/yawn/GetClass/CIM_DeviceSAPImplementation?url=http%3A%2F%2F192.168.1.88%3A5988&verify=0&ns=root%2Fcimv2"
	# sys.stderr.write("cimomNoPort=%s yawnUrl=%s\n"%(cimomNoPort,yawnUrl))
	grph.add( ( wbemNode, pc.property_rdf_data_nolist3, lib_common.NodeUrl(yawnUrl) ) )

# topclassNam is None at first call.
def PrintClassRecu(grph, rootNode, tree_classes, topclassNam, depth, wbemNamespace, cimomUrl, maxDepth, withYawnUrls):
	# sys.stderr.write("topclassNam=%s depth=%d\n" % (topclassNam,depth))

	if depth > maxDepth	:
		return
	depth += 1

	wbemUrl = lib_wbem.ClassUrl( wbemNamespace, cimomUrl, topclassNam )
	wbemNode = lib_common.NodeUrl( wbemUrl )

	grph.add( ( rootNode, pc.property_cim_subclass, wbemNode ) )

	# The class is the starting point when displaying the class tree of the namespace.
	wbemNodeSub = WbemNamespaceNode(wbemNamespace, cimomUrl, topclassNam)
	grph.add( ( wbemNode, pc.property_rdf_data_nolist1, wbemNodeSub ) )

	nodeGeneralisedClass = lib_util.EntityClassNode(topclassNam,wbemNamespace,cimomUrl,"WBEM")
	grph.add( ( wbemNode, pc.property_rdf_data_nolist2, nodeGeneralisedClass ) )

	if withYawnUrls:
		AddYawnNode(cimomUrl,topclassNam,wbemNamespace,grph,wbemNode)

	try:
		# TODO: This should be indexed with a en empty string !
		if topclassNam == "":
			topclassNam = None
		for cl in tree_classes[topclassNam]:
			PrintClassRecu(grph, wbemNode, tree_classes, cl.classname, depth, wbemNamespace, cimomUrl, maxDepth, withYawnUrls)
	except KeyError:
		pass # No subclass.

def Main():
	paramkeyMaxDepth = "Maximum depth"
	paramkeyYawnUrls = "Yawn urls"

	# TODO: The type should really be an integer.
	cgiEnv = lib_common.CgiEnv(
					can_process_remote = True,
					parameters = { paramkeyMaxDepth : 2, paramkeyYawnUrls:False })

	( wbemNamespace, entity_type, entity_namespace_type ) = cgiEnv.GetNamespaceType()

	maxDepth = int(cgiEnv.GetParameters( paramkeyMaxDepth ))
	withYawnUrls = int(cgiEnv.GetParameters( paramkeyYawnUrls ))

	lib_util.Logger().debug("wbemNamespace=%s entity_type=%s entity_namespace_type=%s maxDepth=%d",wbemNamespace, entity_type,entity_namespace_type,maxDepth)

	cimomUrl = cgiEnv.GetHost()

	if str(wbemNamespace) == "":
		lib_common.ErrorMessageHtml("namespace should not be empty. entity_namespace_type="+entity_namespace_type)

	grph = cgiEnv.GetGraph()

	connWbem = lib_wbem.WbemConnection(cimomUrl)

	# entity_type might an empty string.
	rootNode = WbemNamespaceNode(wbemNamespace, cimomUrl, entity_type)

	lib_util.Logger().debug("objtypes_wmi.py cimomUrl=%s entity_type=%s",cimomUrl,entity_type )

	treeClassesFiltered = lib_wbem.GetClassesTreeInstrumented(connWbem,wbemNamespace)

	PrintClassRecu(grph, rootNode, treeClassesFiltered, entity_type, 0, wbemNamespace, cimomUrl, maxDepth, withYawnUrls)

	lib_util.Logger().debug("entity_type=%s", entity_type)

	# If we are not at the top of the tree:
	if entity_type != "":
		# Now, adds the base classes of this one, at least one one level.
		wbemKlass = lib_wbem.WbemGetClassObj(connWbem,entity_type,wbemNamespace)
		if wbemKlass:
			superKlassName = wbemKlass.superclass

			sys.stderr.write("superKlassName=%s\n" % superKlassName)
			# An empty string or None.
			if superKlassName:
				wbemSuperNode = WbemNamespaceNode( wbemNamespace, cimomUrl, superKlassName )
				grph.add( ( wbemSuperNode, pc.property_cim_subclass, rootNode ) )
				klaDescrip = lib_wbem.WbemClassDescription(connWbem,superKlassName,wbemNamespace)
				if not klaDescrip:
					klaDescrip = "Undefined class %s %s" % ( wbemNamespace, superKlassName )
				grph.add( ( wbemSuperNode, pc.property_information, lib_common.NodeLiteral(klaDescrip ) ) )

	cgiEnv.OutCgiRdf("LAYOUT_RECT_TB",[pc.property_cim_subclass])
	# cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
