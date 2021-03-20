#!/usr/bin/env python

"""
WMI object types
"""

import sys
import logging
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
def _class_to_node(wmi_namespace, cimom_url, cls_nam):
	global dict_class_to_node
	try:
		wmi_node = dict_class_to_node[cls_nam]
	except KeyError:
		wmi_url = lib_wmi.ClassUrl(wmi_namespace, cimom_url, cls_nam)
		wmi_node = lib_common.NodeUrl(wmi_url)

		dict_class_to_node[ cls_nam] = wmi_node
	return wmi_node


def _wmi_namespace_node(wmi_namespace, cimom_url, cls_nam):
	wmi_url = lib_wmi.NamespaceUrl(wmi_namespace, cimom_url, cls_nam)
	return lib_common.NodeUrl(wmi_url)


_done_node = set()


def _draw_from_this_base(root_node, wmi_namespace, cimom_url, cls_nam, grph, cls_deriv):
	global _done_node
	wmi_node = _class_to_node(wmi_namespace, cimom_url, cls_nam)

	# The class is the starting point when displaying the class tree of the namespace.
	wmi_node_sub = _wmi_namespace_node(wmi_namespace, cimom_url, cls_nam)
	grph.add((wmi_node, pc.property_rdf_data_nolist1, wmi_node_sub))

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
		for base_class_nam in cls_deriv:

			wmi_base_node = _class_to_node(wmi_namespace, cimom_url, base_class_nam)

			grph.add((wmi_base_node, pc.property_cim_subclass, previous_node))
			grph.add((wmi_base_node, pc.property_information, rdflib.Literal(base_class_nam)))
			previous_node = wmi_base_node
			if base_class_nam in _done_node:
				break

			_done_node.add(base_class_nam)


def _get_derivation(conn_wmi, cls_nam):
	wmi_class = getattr(conn_wmi, cls_nam)
	return  wmi_class.derivation ()


_cache_derivations = {}


def _get_derivation_with_cache(conn_wmi, cls_nam):
	global _cache_derivations
	try:
		return _cache_derivations[ cls_nam]
	except KeyError:
		pass

	deriv = _get_derivation(conn_wmi, cls_nam)
	_cache_derivations[cls_nam] = deriv
	for idx in range(0, len(deriv)):
		loop_class = deriv[idx]
		if loop_class in _cache_derivations:
			break
		_cache_derivations[loop_class] = deriv[idx + 1:]

	return deriv


def Main():
	global dict_class_to_node

	dict_class_to_node = dict()

	paramkey_max_depth = "Maximum depth"

	cgiEnv = lib_common.ScriptEnvironment(
		can_process_remote=True,
		parameters={paramkey_max_depth: 3})

	max_depth = int(cgiEnv.get_parameters(paramkey_max_depth))

	wmi_namespace, entity_type = cgiEnv.get_namespace_type()

	logging.debug("wmi_namespace=%s entity_type=%s", wmi_namespace,entity_type)

	cimom_url = cgiEnv.GetHost()

	# If wmi_namespace, this is not an issue, it is set to "root/CIMV2" by default.

	grph = cgiEnv.GetGraph()

	try:
		conn_wmi = lib_wmi.WmiConnect(cimom_url, wmi_namespace)
	except Exception as exc:
		# wmi_namespace=root\directory\\LDAP Caught:
		# x_wmi: Unexpected COM Error (-2147217375, 'OLE error 0x80041021', None, None)
		lib_common.ErrorMessageHtml("wmi_namespace=%s Caught:%s" % (wmi_namespace, str(exc)))

	root_node = _class_to_node(wmi_namespace, cimom_url, entity_type)

	# rootNodeNameSpace = _wmi_namespace_node(entity_type)
	# grph.add( ( root_node, pc.property_rdf_data_nolist2, lib_util.NodeLiteral(rootNodeNameSpace) ) )
	# def EntityClassNode(entity_type, entity_namespace = "", entity_host = "", category = ""):
	root_generalised_class = lib_util.EntityClassNode(entity_type, wmi_namespace, cimom_url, "WMI")
	grph.add((root_node, pc.property_rdf_data_nolist2, root_generalised_class))

	# TODO: Should add a link to the upper class.
	if entity_type == "":
		for cls_nam in conn_wmi.classes:
			cls_deriv = _get_derivation(conn_wmi, cls_nam)

			if len(cls_deriv) < max_depth:
				_draw_from_this_base(root_node, wmi_namespace, cimom_url, cls_nam, grph, cls_deriv)
	else:
		# Normally this cache contains nodes to classes, but this is the top one.
		dict_class_to_node[entity_type] = root_node

		# This also points to its closest base class or to the namespace.
		top_cls_deriv = _get_derivation(conn_wmi, entity_type)
		if len(top_cls_deriv) == 0:
			top_node = _wmi_namespace_node(wmi_namespace, cimom_url, "")
		else:
			top_node = _wmi_namespace_node(wmi_namespace, cimom_url, top_cls_deriv[0])
		grph.add((top_node, pc.property_cim_subclass, root_node))

		for cls_nam in conn_wmi.subclasses_of(entity_type):
			cls_deriv =  _get_derivation(conn_wmi, cls_nam)

			idx_class = cls_deriv.index(entity_type)
			invert_idx = len(cls_deriv) - idx_class

			# This tree can be very deep so there is a maximum depth.
			if len(cls_deriv) < max_depth + invert_idx:
				# derivation starts by the lowest level to the top.
				_draw_from_this_base(root_node, wmi_namespace, cimom_url, cls_nam, grph, cls_deriv[:idx_class])

	cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_cim_subclass])
	# cgiEnv.OutCgiRdf()


if __name__ == '__main__':
	Main()
