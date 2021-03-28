#!/usr/bin/env python

"""
WBEM classes in namespace
"""

import sys
import logging
import lib_util
import lib_wbem
import lib_common
from lib_properties import pc


def _wbem_namespace_node(wbem_namespace, cimom_url, cls_nam):
    wbemUrl = lib_wbem.NamespaceUrl(wbem_namespace, cimom_url, cls_nam)
    return lib_common.NodeUrl(wbemUrl)


# http://pywbem.github.io/yawn/index.html
# "YAWN stands for "Yet Another WBEM Navigator"
# and provides a way to access WBEM servers and to navigate between the CIM objects returned."
# https://github.com/pywbem/yawn
# TODO: Should check if "Yawn" is running on the target machine.
def _add_yawn_node(cimom_url, topclass_nam, wbem_namespace, grph, wbem_node):
    # We could take lib_util.currentHostname but Yawn is more probably running on a machine where Pegasus is there.
    cimom_no_port = cimom_url.split(":")[1]

    # The character "&" must be escaped TWICE ! ...
    yawn_url = "http:%s/yawn/GetClass/%s?url=%s&amp;amp;verify=0&amp;amp;ns=%s"\
             % (cimom_no_port, topclass_nam, lib_util.EncodeUri(cimom_url), lib_util.EncodeUri(wbem_namespace))

    # "http://192.168.1.88/yawn/GetClass/CIM_DeviceSAPImplementation?url=http%3A%2F%2F192.168.1.88%3A5988&verify=0&ns=root%2Fcimv2"
    grph.add((wbem_node, pc.property_rdf_data_nolist3, lib_common.NodeUrl(yawn_url)))


def _print_class_recu(
        grph, root_node, tree_classes, topclass_nam, depth, wbem_namespace, cimom_url, max_depth, with_yawn_urls):
    """topclassNam is None at first call."""

    if depth > max_depth:
        return
    depth += 1

    wbem_url = lib_wbem.ClassUrl(wbem_namespace, cimom_url, topclass_nam)
    wbem_node = lib_common.NodeUrl(wbem_url)

    grph.add((root_node, pc.property_cim_subclass, wbem_node))

    # The class is the starting point when displaying the class tree of the namespace.
    wbem_node_sub = _wbem_namespace_node(wbem_namespace, cimom_url, topclass_nam)
    grph.add((wbem_node, pc.property_rdf_data_nolist1, wbem_node_sub))

    node_generalised_class = lib_util.EntityClassNode(topclass_nam, wbem_namespace, cimom_url, "WBEM")
    grph.add((wbem_node, pc.property_rdf_data_nolist2, node_generalised_class))

    if with_yawn_urls:
        _add_yawn_node(cimom_url, topclass_nam, wbem_namespace, grph, wbem_node)

    try:
        # TODO: This should be indexed with a en empty string !
        if topclass_nam == "":
            topclass_nam = None
        for cl in tree_classes[topclass_nam]:
            _print_class_recu(grph, wbem_node, tree_classes,
                              cl.classname, depth, wbem_namespace, cimom_url, max_depth, with_yawn_urls)
    except KeyError:
        pass # No subclass.


def Main():
    paramkey_max_depth = "Maximum depth"
    paramkey_yawn_urls = "Yawn urls"

    # TODO: The type should really be an integer.
    cgiEnv = lib_common.ScriptEnvironment(
                    can_process_remote=True,
                    parameters={paramkey_max_depth: 2, paramkey_yawn_urls: False})

    wbem_namespace, entity_type = cgiEnv.get_namespace_type()

    max_depth = int(cgiEnv.get_parameters(paramkey_max_depth))
    with_yawn_urls = int(cgiEnv.get_parameters(paramkey_yawn_urls))

    logging.debug("wbem_namespace=%s entity_type=%s max_depth=%d", wbem_namespace, entity_type, max_depth)

    cimom_url = cgiEnv.GetHost()

    if str(wbem_namespace) == "":
        lib_common.ErrorMessageHtml("namespace should not be empty.")

    grph = cgiEnv.GetGraph()

    try:
        conn_wbem = lib_wbem.WbemConnection(cimom_url)
    except Exception as exc:
        lib_common.ErrorMessageHtml("Connecting to :" + cimom_url + " Caught:" + str(exc))

    # entity_type might an empty string.
    root_node = _wbem_namespace_node(wbem_namespace, cimom_url, entity_type)

    logging.debug("objtypes_wmi.py cimom_url=%s entity_type=%s", cimom_url, entity_type)

    tree_classes_filtered = lib_wbem.GetClassesTreeInstrumented(conn_wbem, wbem_namespace)

    _print_class_recu(grph, root_node, tree_classes_filtered,
                      entity_type, 0, wbem_namespace, cimom_url, max_depth, with_yawn_urls)

    logging.debug("entity_type=%s", entity_type)

    # If we are not at the top of the tree:
    if entity_type != "":
        # Now, adds the base classes of this one, at least one one level.
        wbem_klass = lib_wbem.WbemGetClassObj(conn_wbem, entity_type, wbem_namespace)
        if wbem_klass:
            super_klass_name = wbem_klass.superclass

            logging.debug("super_klass_name=%s", super_klass_name)
            # An empty string or None.
            if super_klass_name:
                wbem_super_node = _wbem_namespace_node(wbem_namespace, cimom_url, super_klass_name)
                grph.add((wbem_super_node, pc.property_cim_subclass, root_node))
                kla_descrip = lib_wbem.WbemClassDescription(conn_wbem,super_klass_name,wbem_namespace)
                if not kla_descrip:
                    kla_descrip = "Undefined class %s %s" % (wbem_namespace, super_klass_name)
                grph.add((wbem_super_node, pc.property_information, lib_util.NodeLiteral(kla_descrip)))

    cgiEnv.OutCgiRdf("LAYOUT_RECT_TB", [pc.property_cim_subclass])
    # cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
