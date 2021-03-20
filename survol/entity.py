#!/usr/bin/env python

"""
Overview
"""

import sys
import logging
import lib_util
import lib_common
from lib_properties import pc
import entity_dirmenu_only # Also used with the CGI parameter mode=menu
from sources_types import CIM_Process
from sources_types import CIM_ComputerSystem


__author__      = "Remi Chateauneu"
__copyright__   = "Copyright 2020-2021, Primhill Computers"
__license__     = "GPL"


FunctionGetUser = CIM_Process.GetCurrentUser


def _add_default_nodes(grph, root_node, entity_host):
    logging.debug("entity.py _add_default_nodes entity_host=%s", entity_host)
    current_node_hostname = lib_common.gUriGen.HostnameUri(lib_util.currentHostname)
    grph.add((current_node_hostname,
              pc.property_information,
              lib_util.NodeLiteral("Current host:" + lib_util.currentHostname)))
    grph.add((root_node, pc.property_rdf_data_nolist2, current_node_hostname))

    curr_username = FunctionGetUser()
    current_node_user = lib_common.gUriGen.UserUri(curr_username)
    grph.add((current_node_user, pc.property_information, lib_util.NodeLiteral("Current user:" + curr_username)))
    grph.add((root_node, pc.property_rdf_data_nolist2, current_node_user))


# TODO: Maybe the property should be property_script ??
def _add_default_scripts(grph, root_node, entity_host):
    logging.debug("entity.py _add_default_scripts entity_host=%s", entity_host)
    node_obj_types = lib_common.NodeUrl(lib_util.uriRoot + '/objtypes.py')
    grph.add((root_node, pc.property_rdf_data_nolist2, node_obj_types))

    # Gives a general access to WBEM servers. In fact we might iterate on several servers, or none.
    node_portal_wbem = lib_util.UrlPortalWbem(entity_host)
    grph.add((root_node, pc.property_rdf_data_nolist2, node_portal_wbem))

    # Gives a general access to WMI servers.
    node_portal_wmi = lib_util.UrlPortalWmi(entity_host)
    grph.add((root_node, pc.property_rdf_data_nolist2, node_portal_wmi))


def _add_wbem_wmi_servers(grph, root_node, entity_host, name_space, entity_type, entity_id):
    """This adds the WBEM and WMI urls related to the entity:
    URLs pointing to the class, to the object itself etc...
    This is used to add as muich informaton as possible about an object.
    A possible difficulty is the correct escaping of special characters in the definition. """

    # Beware that commas and special characteres should be properly escaped.

    if entity_host:
        host_wbem_wmi = entity_host
    else:
        host_wbem_wmi = lib_util.currentHostname

    # This receives a map and a RDF property, and must add the corresponding nodes to the root_node
    # int the given graph. The same callback signature is used elsewhere to generate HTML tables.
    def add_w_map(the_map, prop_data):
        if the_map:
            for url_subj in the_map:
                grph.add((root_node, prop_data, url_subj))
                for the_prop, url_obj in the_map[url_subj]:
                    grph.add((url_subj, the_prop, url_obj))

    map_wbem = CIM_ComputerSystem.AddWbemServers(host_wbem_wmi, name_space, entity_type, entity_id)
    add_w_map(map_wbem, pc.property_wbem_data)
    map_wmi = CIM_ComputerSystem.AddWmiServers(host_wbem_wmi, name_space, entity_type, entity_id)
    add_w_map(map_wmi, pc.property_wmi_data)
    map_survol = CIM_ComputerSystem.AddSurvolServers(host_wbem_wmi, name_space, entity_type, entity_id)
    add_w_map(map_survol, pc.property_survol_agent)



# Under the directory sources_types, each module is defined by its ontology,
# or none. If a module has an ontology, then it represents a class.
# An ontology is a small list of keywords (most of times only one),
# each representing an attribute of the object of this class.
# If a module, in the directory sources_types, has no ontology, then it uses
# the ontology of the upper directory, or higher in the hierarchy etc...
# If, at the end, it still has no ontology, then it does not represent a class
# but is simply used as a namespace, or a domain of interest.
# For example: "sources_types/Azure" is not a class in itself but contains
# all the modules - and the classes - defined by Azure: Location, subscription etc...


def Main():

    # This can process remote hosts because it does not call any script, just shows them.
    cgiEnv = lib_common.ScriptEnvironment(
                    can_process_remote=True,
                    parameters={lib_util.paramkeyShowAll: False})
    entity_id = cgiEnv.m_entity_id
    entity_host = cgiEnv.GetHost()
    logging.debug("entity_host=%s", entity_host)
    flag_show_all = int(cgiEnv.get_parameters(lib_util.paramkeyShowAll))

    name_space, entity_type = cgiEnv.get_namespace_type()

    grph = cgiEnv.GetGraph()

    root_node = lib_util.RootUri()
    logging.debug("root_node=%s", root_node)

    entity_ids_arr = lib_util.EntityIdToArray(entity_type, entity_id)

    # Each entity type ("process","file" etc... ) can have a small library
    # of its own, for displaying a rdf node of this type.
    if entity_type:
        entity_module = lib_util.GetEntityModule(entity_type)
        if entity_module:
            try:
                entity_module.AddInfo(grph, root_node, entity_ids_arr)
            except AttributeError as exc:
                logging.info("entity.py No AddInfo for %s %s: %s", entity_type, entity_id, str(exc))
            except Exception as exc:
                logging.info("entity.py Unexpected exception for %s %s: %s", entity_type, entity_id, str(exc))
    else:
        logging.info("No lib_entities for %s %s", entity_type, entity_id)

    # When displaying in json mode, the scripts are shown with a contextual menu, not with D3 modes..
    if lib_util.GuessDisplayMode() not in ["json", "html"]:

        # This function is called for each script which applies to the given entity.
        # It receives a triplet: (subject,property,object) and the depth in the tree.
        # Here, this simply stores the scripts in a graph. The depth is not used yet,
        # but can help debugging.
        def callback_grph_add(tripl, depthCall):
            try:
                grph.add(tripl)
            except Exception as exc:
                logging.error("callback_grph_add: tripl=%s exception=%s" % (str(tripl), str(exc)))
                raise

        try:
            entity_dirmenu_only.recursive_walk_on_scripts(callback_grph_add, root_node, entity_type, entity_id, entity_host, flag_show_all)
        except Exception as exc:
            logging.error("entity.py caught in ForToMenu:%s", exc)

        # This adds WBEM and WMI urls related to the current object.
        if entity_type != "":
            # This solves the case where one of the values of the ontology predicates contains commas.
            # These commands were quoted, then separated of other arguments by a comma.
            # TODO: It would be probably be  simpler to encode predicates values just like CGI arguments.
            _add_wbem_wmi_servers(grph, root_node, entity_host, name_space, entity_type, entity_id)

        _add_default_scripts(grph, root_node, entity_host)

        # Special case if the current entity we are displaying, is a machine,
        # we might as well try to connect to its WMI or WBEM server, running on this machine.
        if entity_type == "CIM_ComputerSystem":
            _add_default_scripts(grph, root_node, entity_id)

    _add_default_nodes(grph, root_node, entity_host)

    cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_directory, pc.property_script])


if __name__ == '__main__':
    Main()

