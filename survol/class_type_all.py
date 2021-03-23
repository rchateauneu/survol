#!/usr/bin/env python

"""
Generalised class: Displays data sources for a class
"""

import os
import sys

import lib_uris
import lib_util
import lib_common
import logging

try:
    import lib_wbem
    wbem_ok = True
except ImportError:
    wbem_ok = False
import lib_wmi
from lib_properties import pc


def _wbem_add_base_class(grph, conn_wbem, wbem_node, entity_host, wbem_namespace, entity_type):
    # Adds the base classes of this one, at least one one level."""
    wbem_klass = lib_wbem.WbemGetClassObj(conn_wbem, entity_type, wbem_namespace)
    if not wbem_klass:
        return None, None

    super_klass_name = wbem_klass.superclass

    # An empty string or None.
    if not super_klass_name:
        return None, None

    # TODO: Should be changed, this is slow and inconvenient.
    wbem_super_urls_list = lib_wbem.GetWbemUrls(entity_host, wbem_namespace, super_klass_name, "")
    if not wbem_super_urls_list:
        return None, None

    # TODO: Which one should we take, http or https ???
    wbem_super_url = wbem_super_urls_list[0][0]
    logging.debug("WBEM wbem_super_url=%s", wbem_super_url)

    wbem_super_node = lib_common.NodeUrl(wbem_super_url)

    grph.add((wbem_super_node, pc.property_cim_subclass, wbem_node))
    kla_descrip = lib_wbem.WbemClassDescription(conn_wbem, super_klass_name, wbem_namespace)
    if not kla_descrip:
        kla_descrip = "Undefined class %s %s" % (wbem_namespace, super_klass_name)
    grph.add((wbem_super_node, pc.property_information, lib_util.NodeLiteral(kla_descrip)))

    return wbem_super_node, super_klass_name


def _wbem_add_all_base_classes(grph, conn_wbem, wbem_node, entity_host, wbem_namespace, entity_type):
    """Adds the list of base classes. Returns the list of pairs (name node),
    so it can be matched against another inheritance tree."""
    pair_name_node = dict()
    while wbem_node:
        wbem_super_node, super_class = _wbem_add_base_class(
            grph, conn_wbem, wbem_node, entity_host, wbem_namespace, entity_type)
        pair_name_node[entity_type] = wbem_node
        wbem_node = wbem_super_node
        entity_type = super_class
    return pair_name_node


def _create_wbem_node(grph, root_node, entity_host, name_space, class_name, entity_id):
    wbem_namespace = name_space.replace("\\", "/")
    wbem_servers_desc_list = lib_wbem.GetWbemUrls(entity_host, wbem_namespace, class_name, entity_id)

    # If there are no servers.
    pair_name_node = None

    for url_server in wbem_servers_desc_list:
        wbem_node = lib_common.NodeUrl(url_server[0])
        grph.add((root_node, pc.property_wbem_data, wbem_node))

        wbemHostNode = lib_uris.gUriGen.HostnameUri(url_server[1])
        grph.add((wbem_node, pc.property_host, wbemHostNode))

        # TODO: Add a Yawn server ??
        grph.add((wbem_node, pc.property_wbem_server, lib_util.NodeLiteral(url_server[1])))

        # Now adds the description of the class.
        try:
            conn_wbem = lib_wbem.WbemConnection(entity_host)
        except Exception as exc:
            logging.error("WbemConnection throw:%s" % str(exc))
            continue

        kla_descrip = lib_wbem.WbemClassDescription(conn_wbem, class_name, wbem_namespace)
        ok_wbem_class = True
        if not kla_descrip:
            ok_wbem_class = False
            kla_descrip = "Undefined class %s %s" % (wbem_namespace, class_name)
        grph.add((wbem_node, pc.property_information, lib_util.NodeLiteral(kla_descrip)))

        # Maybe this class is not Known in WBEM.
        try:
            pair_name_node = _wbem_add_all_base_classes(grph, conn_wbem, wbem_node, entity_host, name_space, class_name)
        except:
            pair_name_node = None

        if ok_wbem_class and wbem_ok and name_space != "" and entity_host != "":
            namespace_url = lib_wbem.NamespaceUrl(name_space, entity_host, class_name)
            namespace_node = lib_common.NodeUrl(namespace_url)
            grph.add((wbem_node, pc.property_information, namespace_node))

    # TODO: This is a bit absurd because we return just one list.
    return pair_name_node


def _create_wmi_node(grph, root_node, entity_host, name_space, class_name, entity_id):
    """Adds a WMI node and other stuff, for the class name."""
    wmiurl = lib_wmi.GetWmiUrl(entity_host, name_space, class_name, entity_id)
    if wmiurl is None:
        return

    # There might be "http:" or the port number around the host.
    wmi_node = lib_common.NodeUrl(wmiurl)
    grph.add((root_node, pc.property_wmi_data, wmi_node))

    # TODO: Shame, we just did it in GetWmiUrl.
    ip_only = lib_util.EntHostToIp(entity_host)
    try:
        # It simply returns if it cannot connect.
        conn_wmi = lib_wmi.WmiConnect(ip_only, name_space, False)
        if not conn_wmi:
            raise Exception("Cannot connect")
        lib_wmi.WmiAddClassQualifiers(grph, conn_wmi, wmi_node, class_name, False)

        # Now displays the base classes, to the top of the inheritance tree.
        pair_name_node = lib_wmi.WmiAddBaseClasses(grph, conn_wmi, wmi_node, ip_only, name_space, class_name)

    except Exception as exc:
        pair_name_node = None
        # TODO: If the class is not defined, maybe do not display it.
        err_msg = "WMI connection %s: %s" % (ip_only, str(exc))
        grph.add((wmi_node, lib_common.MakeProp("WMI Error"), lib_util.NodeLiteral(err_msg)))

    url_name_space = lib_wmi.NamespaceUrl(name_space, ip_only, class_name)
    # sys.stderr.write("entity_host=%s url_name_space=%s\n"%(entity_host,url_name_space))
    grph.add((wmi_node, pc.property_information, lib_common.NodeUrl(url_name_space)))

    return pair_name_node


def AddCIMClasses(grph, root_node, entity_host, name_space, class_name, entity_id):
    """entity_type = "CIM_Process", "Win32_Service" etc...
    This might happen at an intermediary level, with inheritance (To be implemented).
    Maybe some of these servers are not able to display anything about this object."""

    pair_name_node_wbem = None
    if wbem_ok:
        if lib_wbem.ValidClassWbem(class_name):
            pair_name_node_wbem = _create_wbem_node(grph, root_node, entity_host, name_space, class_name, entity_id)

    pair_name_node_wmi = None
    if lib_wmi.ValidClassWmi(class_name):
        pair_name_node_wmi = _create_wmi_node(grph, root_node, entity_host, name_space, class_name, entity_id)

    # Match the two inheritance trees.
    if pair_name_node_wbem and pair_name_node_wmi:
        for base_cls_nam, node_wbem in lib_util.six_iteritems(pair_name_node_wbem):
            try:
                nodeWmi = pair_name_node_wmi[base_cls_nam]
            except KeyError:
                continue

            node_cls_all = lib_util.EntityClassNode(base_cls_nam, name_space, entity_host, "WBEM ou WMI")
            grph.add((node_cls_all, pc.property_wbem_data, node_wbem))
            grph.add((node_cls_all, pc.property_wmi_data, nodeWmi))


def _create_our_node(grph, root_node, entity_host, name_space, class_name, entity_id):
    """This try to find a correct url for an entity type, without an entity id.
    At the moment, we just expect a file called "enumerate_<entity>.py" """
    enumerate_script = "enumerate_" + class_name + ".py"

    base_dir = lib_util.gblTopScripts + "/sources_types"

    # TODO: This is absurd !!! Why looping, because the filename is already known !?!?
    for dirpath, dirnames, filenames in os.walk(base_dir):
        for filename in [f for f in filenames if f == enumerate_script]:

            short_dir = dirpath[len(lib_util.gblTopScripts):]
            full_script_nam = lib_util.standardized_file_path(os.path.join(short_dir, filename))
            logging.debug("full_script_nam=%s", full_script_nam)

            # TODO: Maybe remove the beginning of the file.
            local_class_url = lib_util.ScriptizeCimom(full_script_nam, class_name, entity_host)

            local_class_node =  lib_common.NodeUrl(local_class_url)
            grph.add((root_node, pc.property_directory, local_class_node))


def Main():
    """This should be able to process remote hosts because it calls scripts which can access remote data."""
    cgiEnv = lib_common.ScriptEnvironment(can_process_remote=True)

    name_space, class_name = cgiEnv.get_namespace_type()

    # If name_space is not provided, it is set to "root/CIMV2" by default.
    if not class_name:
        lib_common.ErrorMessageHtml("Class name should not be empty")

    # Just in case ...
    if name_space == "/":
        name_space = ""

    entity_host = cgiEnv.GetHost()
    entity_id = cgiEnv.m_entity_id

    # QUERY_STRING=xid=http%3A%2F%2F192.168.1.88%3A5988%2Froot%2FPG_Internal%3APG_WBEMSLPTemplate
    logging.debug("class_type_all entity_host=%s entity_id=%s", entity_host, entity_id)

    grph = cgiEnv.GetGraph()

    root_node = lib_util.RootUri()

    objtypeNode = lib_common.NodeUrl(lib_util.uriRoot + '/objtypes.py')
    grph.add((root_node, pc.property_rdf_data_nolist2, objtypeNode))

    # This displays the documentation of the Python module of this entity class.
    entity_module = lib_util.GetEntityModule(class_name)
    ent_doc = entity_module.__doc__
    if ent_doc:
        ent_doc = ent_doc.strip()
        grph.add((root_node, pc.property_information, lib_util.NodeLiteral(ent_doc)))

    _create_our_node(grph, root_node, entity_host, name_space, class_name, entity_id)

    # Do this for each intermediary entity type (Between slashes).
    AddCIMClasses(grph, root_node, entity_host, name_space, class_name, entity_id)

    cgiEnv.OutCgiRdf("LAYOUT_RECT_TB")


if __name__ == '__main__':
    Main()
