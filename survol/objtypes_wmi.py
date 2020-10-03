#!/usr/bin/env python

"""
WMI object types
"""

import sys
import lib_util
import rdflib
import lib_common
from lib_properties import pc

try:
	import wmi
except ImportError:
	lib_common.ErrorMessageHtml("Python package WMI is not available")
import lib_wmi


# Manages a cache so nodes are created once only.
def ClassToNode(wmiNamespace, cimomUrl, clsNam):
	global dictClassToNode
	try:
		wmi_node = dictClassToNode[ clsNam ]
	except KeyError:
		wmi_url = lib_wmi.ClassUrl(wmiNamespace,cimomUrl,clsNam)
		wmi_node = lib_common.NodeUrl( wmi_url )

		dictClassToNode[ clsNam ] = wmi_node
	return wmi_node

def WmiNamespaceNode( wmiNamespace, cimomUrl, clsNam):
	wmi_url = lib_wmi.NamespaceUrl(wmiNamespace, cimomUrl, clsNam)
	return lib_common.NodeUrl(wmi_url)


_done_node = set()


def DrawFromThisBase(root_node, wmi_namespace, cimom_url, cls_nam, grph, cls_deriv):
	global _done_node
	wmi_node = ClassToNode(wmi_namespace, cimom_url, cls_nam)

	# The class is the starting point when displaying the class tree of the namespace.
	wmi_node_sub = WmiNamespaceNode(wmi_namespace, cimom_url, cls_nam)
	grph.add( ( wmi_node, pc.property_rdf_data_nolist1, wmi_node_sub))

	node_generalised_class = lib_util.EntityClassNode(cls_nam, wmi_namespace, cimom_url, "WMI")
	grph.add((wmi_node, pc.property_rdf_data_nolist2, node_generalised_class))
	grph.add((wmi_node, pc.property_information, rdflib.Literal(cls_nam)))

	_done_node.add(cls_nam)

	previous_node = wmi_node

	# TODO: Collapse the two case into one, for cleanliness.
	if len(cls_deriv) == 0:
		grph.add((root_node, pc.property_cim_subclass, previous_node))
	else:
		# sys.stderr.write("cls_nam=%s cls_deriv=%s\n" % ( cls_nam, str(cls_deriv) ))
		for baseClassNam in cls_deriv:

			wmi_base_node = ClassToNode(wmi_namespace, cimom_url, baseClassNam)

			grph.add((wmi_base_node, pc.property_cim_subclass, previous_node))
			grph.add((wmi_base_node, pc.property_information, rdflib.Literal(baseClassNam)))
			previous_node = wmi_base_node
			if baseClassNam in _done_node:
				break

			_done_node.add(baseClassNam)


def GetDerivation(conn_wmi, cls_nam):
	wmi_class = getattr(conn_wmi, cls_nam)
	return  wmi_class.derivation ()


cacheDerivations = {}


# Not sure this is faster.
def GetDerivationWithCache(conn_wmi, cls_nam):
	global cacheDerivations
	try:
		return cacheDerivations[ cls_nam]
	except KeyError:
		pass

	deriv = GetDerivation(conn_wmi, cls_nam)
	cacheDerivations[cls_nam] = deriv
	for idx in range(0, len(deriv)):
		loopClass = deriv[idx]
		if loopClass in cacheDerivations:
			break
		cacheDerivations[loopClass] = deriv[idx+1:]

	return deriv


def Main():
	global dictClassToNode

	dictClassToNode = dict()

	paramkeyMaxDepth = "Maximum depth"

	cgiEnv = lib_common.CgiEnv(can_process_remote = True,
									parameters = { paramkeyMaxDepth : 3 })

	maxDepth = int(cgiEnv.get_parameters( paramkeyMaxDepth ))

	wmi_namespace, entity_type = cgiEnv.get_namespace_type()

	DEBUG("wmi_namespace=%s entity_type=%s", wmi_namespace,entity_type)

	cimom_url = cgiEnv.GetHost()

	# If wmi_namespace, this is not an issue, it is set to "root/CIMV2" by default.

	grph = cgiEnv.GetGraph()

	try:
		conn_wmi = lib_wmi.WmiConnect(cimom_url, wmi_namespace)
	except:
		exc = sys.exc_info()[1]
		# wmi_namespace=root\directory\\LDAP Caught:
		# x_wmi: Unexpected COM Error (-2147217375, 'OLE error 0x80041021', None, None)
		lib_common.ErrorMessageHtml("wmi_namespace=%s Caught:%s" % (wmi_namespace, str(exc)))

	root_node = ClassToNode(wmi_namespace, cimom_url, entity_type)

	# rootNodeNameSpace = WmiNamespaceNode(entity_type)
	# grph.add( ( root_node, pc.property_rdf_data_nolist2, lib_common.NodeLiteral(rootNodeNameSpace) ) )
	# def EntityClassNode(entity_type, entity_namespace = "", entity_host = "", category = ""):
	rootGeneralisedClass = lib_util.EntityClassNode(entity_type, wmi_namespace, cimom_url, "WMI")
	grph.add((root_node, pc.property_rdf_data_nolist2, rootGeneralisedClass))

	# TODO: Should add a link to the upper class.
	if entity_type == "":
		for cls_nam in conn_wmi.classes:
			cls_deriv = GetDerivation(conn_wmi, cls_nam)

			if len(cls_deriv) < maxDepth:
				DrawFromThisBase(root_node, wmi_namespace, cimom_url, cls_nam,grph, cls_deriv)
	else:
		# Normally this cache contains nodes to classes, but this is the top one.
		dictClassToNode[entity_type] = root_node

		# This also points to its closest base class or to the namespace.
		top_cls_deriv = GetDerivation(conn_wmi, entity_type)
		if len(top_cls_deriv) == 0:
			top_node = WmiNamespaceNode(wmi_namespace, cimom_url, "")
		else:
			top_node = WmiNamespaceNode(wmi_namespace, cimom_url, top_cls_deriv[0])
		grph.add((top_node, pc.property_cim_subclass, root_node))

		for cls_nam in conn_wmi.subclasses_of(entity_type):
			cls_deriv =  GetDerivation(conn_wmi, cls_nam)

			idx_class = cls_deriv.index(entity_type)
			invert_idx = len(cls_deriv) - idx_class

			# This tree can be very deep so there is a maximum depth.
			if len(cls_deriv) < maxDepth + invert_idx:
				# derivation starts by the lowest level to the top.
				DrawFromThisBase(root_node, wmi_namespace, cimom_url, cls_nam,grph, cls_deriv[:idx_class])

	cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_cim_subclass])
	# cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
