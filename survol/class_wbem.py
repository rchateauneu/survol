#!/usr/bin/env python

"""
WBEM class portal: Display all instances of a given WBEM class
"""

import sys
import cgi
import logging
import urllib
import lib_util
import lib_common
import lib_wbem
from lib_properties import pc

import pywbem # Might be pywbem or python3-pywbem.

# TODO: Add link to http://schemas.dmtf.org/wbem/cim-html/2.49.0/CIM_Directory.html
# Also consider https://www.ibm.com/support/knowledgecenter/en/SSLTBW_2.1.0/com.ibm.zos.v2r1.cfzu100/ibmzos_computersystem.htm


def _assoc_reference_to_node(name_space, entity_host, assoc_inst):
	assoc_class = assoc_inst.classname

	assoc_key_val_pairs = assoc_inst.keybindings

	# The natural conversion to a string makes a perfect url, But we need to extract the components:
	# str(valAssoc) = 'root/cimv2:LMI_DiskDrive.CreationClassName="LMI_DiskDrive",SystemName="Unknown-30-b5-c2-02-0c-b5-2.home"'

	assoc_entity_id = ",".join("%s=%s" % (k, assoc_key_val_pairs[k]) for k in assoc_key_val_pairs)

	# The association and the references are probably in the same namespace.
	wbem_assoc_url = lib_wbem.WbemInstanceUrl(name_space, assoc_class, assoc_entity_id, entity_host)
	wbem_assoc_node = lib_common.NodeUrl(wbem_assoc_url)
	return wbem_assoc_node


def _display_associators_as_network(grph, inst_names, root_node, name_space, entity_host, max_instances, start_index):
	"""Display the graph of associations. It can work only if there are only two references in each instance."""
	max_cnt = 0
	for iname in inst_names:
		if start_index > 0:
			start_index -= 1
			continue

		if max_cnt == max_instances:
			break
		max_cnt += 1

		# For the moment, references are not added to the Moniker, otherwise the syntax would be too complicated, like:
		# wbemInstName=root/CIMv2:TUT_ProcessChild.Parent="root/cimv2:TUT_UnixProcess.Handle="1"",Child="root/cimv2:TUT_UnixProcess.Handle="621"",OSCreationClassName="Linux_OperatingSystem",CSName="Unknown-30-b5-c2-02-0c-b5-2.home",CSCreationClassName="Linux_ComputerSystem",CreationClassName="TUT_UnixProcess",OSName="Unknown-30-b5-c2-02-0c-b5-2.home"

		# Do not care about the instance.

		node_previous = None
		key_previous = None

		for key_assoc in iname.keys():
			assoc_inst = iname[key_assoc]

			# If this happens, it could be used as a qualifier for the edge.
			if not isinstance(assoc_inst, pywbem.CIMInstanceName):
				lib_common.ErrorMessageHtml("Inconsistency, members should be instances: __name__=%s" % type(assoc_inst).__name__)

			wbem_assoc_node = _assoc_reference_to_node(name_space, entity_host, assoc_inst)

			# We lose the name of the previous property.
			if not node_previous is None:
				grph.add((node_previous, lib_common.MakeProp(key_previous + "-" + key_assoc), wbem_assoc_node))

			key_previous = key_assoc
			node_previous = wbem_assoc_node


def _display_associators_as_list(grph, inst_names, root_node, name_space, entity_host, class_name, max_instances, start_index):
	"""Display one line per instance of the class as members were literals.
	This attempts to display the references as links. It does not really work yet,
	because "special" properties" have to be used."""
	max_cnt = 0
	for iname in inst_names:
		if start_index > 0:
			start_index -= 1
			continue

		if max_cnt == max_instances:
			break
		max_cnt += 1

		# For the moment, references are not added to the Moniker, otherwise the syntax would be too complicated, like:
		# wbemInstName=root/CIMv2:TUT_ProcessChild.Parent="root/cimv2:TUT_UnixProcess.Handle="1"",Child="root/cimv2:TUT_UnixProcess.Handle="621"",OSCreationClassName="Linux_OperatingSystem",CSName="Unknown-30-b5-c2-02-0c-b5-2.home",CSCreationClassName="Linux_ComputerSystem",CreationClassName="TUT_UnixProcess",OSName="Unknown-30-b5-c2-02-0c-b5-2.home"

		entity_id = ",".join("%s=%s" % (k, iname[k]) for k in iname.keys())

		wbem_instance_url = lib_wbem.WbemInstanceUrl(name_space, class_name, entity_id, entity_host)
		wbem_instance_node = lib_common.NodeUrl(wbem_instance_url)

		# On va ajouter une colonne par reference.
		for key_assoc in iname.keys():
			assoc_inst = iname[key_assoc]

			wbem_assoc_node = _assoc_reference_to_node(name_space, entity_host, assoc_inst)
			grph.add((wbem_instance_node, lib_common.MakeProp(key_assoc), wbem_assoc_node))

		grph.add((root_node, pc.property_class_instance, wbem_instance_node))


def _display_plain_class(grph, inst_names, root_node, name_space, entity_host, class_name, max_instances, start_index):
	"""Display one line per instance of the class. Members are literals
	because this is not an associator. Still, it works with an associator."""
	max_cnt = 0

	# This is for normal classes.
	for iname in inst_names:
		if start_index > 0:
			start_index -= 1
			continue

		if max_cnt == max_instances:
			break
		max_cnt += 1

		# This concatenates all the properties, even the ones which are not in the Survol ontology.
		# This makes sense because we do not know if this class if known by Survol.
		entity_id = ",".join("%s=%s" % (k, iname[k]) for k in iname.keys())
		wbem_instance_url = lib_wbem.WbemInstanceUrl(name_space, class_name, entity_id, entity_host)

		wbem_instance_node = lib_common.NodeUrl(wbem_instance_url)

		grph.add((root_node, pc.property_class_instance, wbem_instance_node))


def Main():
	paramkey_max_instances = "Max instances"
	paramkey_start_index = "Start index"

	# This can process remote hosts because it does not call any script, just shows them.
	cgiEnv = lib_common.ScriptEnvironment(can_process_remote = True,
									parameters = {paramkey_max_instances: 80, paramkey_start_index: 0})

	max_instances = cgiEnv.get_parameters(paramkey_max_instances)
	start_index = cgiEnv.get_parameters(paramkey_start_index)

	grph = cgiEnv.GetGraph()

	name_space, class_name = cgiEnv.get_namespace_type()
	logging.debug("name_space=%s class_name=%s", name_space, class_name)

	entity_host = cgiEnv.GetHost()

	root_node = lib_util.EntityClassNode(class_name, name_space, entity_host, "WBEM")

	# Hard-coded default namespace.
	if name_space == "":
		name_space = "root/CIMV2"

	# This adds a link to the namespace of this WBEM class: It shows its inheritance graph.
	url_namespace = lib_wbem.NamespaceUrl(name_space, entity_host, class_name)
	nod_namespace = lib_common.NodeUrl(url_namespace)
	grph.add((root_node, pc.property_cim_subnamespace, nod_namespace))

	try:
		conn_wbem = lib_wbem.WbemConnection(entity_host)
		wbem_klass = conn_wbem.GetClass(class_name, namespace=name_space, LocalOnly=False, IncludeQualifiers=True)
	except Exception as exc:
		lib_common.ErrorMessageHtml(
			"EnumerateInstanceNames: entity_host=" + entity_host
			+ " name_space="+name_space
			+ " class_name="+class_name+". Caught:"+str(exc))

	kla_descrip = lib_wbem.WbemClassDescrFromClass(wbem_klass)
	grph.add((root_node, pc.property_information, lib_util.NodeLiteral("WBEM description: " + kla_descrip)))

	# WBEM and WMI both have the annoying limitation that it is not possible to select only a range of instances.
	try:
		inst_names = conn_wbem.EnumerateInstanceNames(ClassName=class_name, namespace=name_space)
	except Exception as exc:
		lib_common.ErrorMessageHtml(
			"EnumerateInstanceNames: entity_host="+entity_host
			+ " name_space="+name_space+" class_name="
			+ class_name+". Caught:"+str(exc))

	try:
		is_association = wbem_klass.qualifiers['Association'].value
	except KeyError:
		is_association = False

	# It is possible to display an association like a normal class but it is useless.
	if is_association:
		if True:
			_display_associators_as_network(grph, inst_names, root_node, name_space, entity_host, max_instances, start_index)
		else:
			_display_associators_as_list(grph, inst_names, root_node, name_space, entity_host, class_name, max_instances, start_index)
	else:
		_display_plain_class(grph, inst_names, root_node, name_space, entity_host, class_name, max_instances, start_index)

	num_instances = len(inst_names)
	logging.debug("num_instances=%d start_index=%d",num_instances,start_index)

	# This displays one link on the same page, with specific values of these parameters.
	# The other parameters are not changed.
	# TODO, BEWARE: What is the total number of elements ?
	if start_index + max_instances < num_instances:
		cgiEnv.add_parameterized_links("Next", {paramkey_start_index: start_index + max_instances})
	if start_index > 0:
		cgiEnv.add_parameterized_links("Previous", {paramkey_start_index: max(start_index - max_instances, 0)})

	cgiEnv.OutCgiRdf("LAYOUT_RECT",[pc.property_class_instance])


if __name__ == '__main__':
	Main()
