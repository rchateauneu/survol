#!/usr/bin/env python

"""
Overview
"""

import lib_util
import lib_common
from lib_properties import pc
import entity_dirmenu_only # Also used with the CGI parameter mode=menu
from sources_types import CIM_Process
from sources_types import CIM_ComputerSystem


__author__      = "Remi Chateauneu"
__copyright__   = "Copyright 2020, Primhill Computers"
__license__     = "GPL"


FunctionGetUser = CIM_Process.GetCurrentUser


def _add_default_nodes(grph, root_node, entity_host):
    DEBUG("entity.py _add_default_nodes entity_host=%s", entity_host)
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
    DEBUG("entity.py _add_default_scripts entity_host=%s",entity_host)
    node_obj_types = lib_common.NodeUrl(lib_util.uriRoot + '/objtypes.py')
    grph.add((root_node, pc.property_rdf_data_nolist2, node_obj_types))

    # Gives a general access to WBEM servers. In fact we might iterate on several servers, or none.
    node_portal_wbem = lib_util.UrlPortalWbem(entity_host)
    grph.add((root_node, pc.property_rdf_data_nolist2, node_portal_wbem))

    # Gives a general access to WMI servers.
    node_portal_wmi = lib_util.UrlPortalWmi(entity_host)
    grph.add((root_node, pc.property_rdf_data_nolist2, node_portal_wmi))


################################################################################

# Under the directory sources_types, each module is defined by its ontology,
# or none. If a module has an ontology, then its represents a class.
# An ontology is a small list of keywords, each representing an attribute
# of the object of this class.
# If a module, in the directory sources_types, has no ontology, then it uses
# the ontology of the upper directory, or more higher in the hierarchy etc...
# If, at the end, it still has no ontology, then it does not represent a class
# but is simply used as a namespace. Fro example: "sources_types/Azure"
# is not a class in itself but contains all the modules - and the classes - defined
# by Azure: Location, subscription etc...

################################################################################

def Main():

    # This can process remote hosts because it does not call any script, just shows them.
    cgiEnv = lib_common.CgiEnv(
                    can_process_remote=True,
                    parameters={lib_util.paramkeyShowAll: False})
    entity_id = cgiEnv.m_entity_id
    entity_host = cgiEnv.GetHost()
    DEBUG("entity_host=%s", entity_host)
    flagShowAll = int(cgiEnv.get_parameters(lib_util.paramkeyShowAll))

    name_space, entity_type = cgiEnv.get_namespace_type()

    grph = cgiEnv.GetGraph()

    root_node = lib_util.RootUri()
    DEBUG("root_node=%s", root_node)

    entity_ids_arr = lib_util.EntityIdToArray(entity_type, entity_id)

    # Each entity type ("process","file" etc... ) can have a small library
    # of its own, for displaying a rdf node of this type.
    if entity_type:
        entity_module = lib_util.GetEntityModule(entity_type)
        if entity_module:
            try:
                entity_module.AddInfo(grph, root_node, entity_ids_arr)
            except AttributeError as exc:
                INFO("entity.py No AddInfo for %s %s: %s", entity_type, entity_id, str(exc))
            except Exception as exc:
                INFO("entity.py Unexpected exception for %s %s: %s", entity_type, entity_id, str(exc))
    else:
        INFO("No lib_entities for %s %s", entity_type, entity_id)

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
                ERROR("callback_grph_add: tripl=%s exception=%s" % (str(tripl), str(exc)))
                raise

        try:
            entity_dirmenu_only.DirToMenu(callback_grph_add, root_node, entity_type, entity_id, entity_host, flagShowAll)
        except Exception as exc:
            ERROR("entity.py caught in ForToMenu:%s", exc)

        # This adds WBEM and WMI urls related to the current object.
        if entity_type != "":
            CIM_ComputerSystem.AddWbemWmiServers(grph, root_node, entity_host, name_space, entity_type, entity_id)

        _add_default_scripts(grph, root_node, entity_host)

        # Special case if the currententity we are displaying, is a machine,
        # we might as well try to connect to its WMI or WBEM server, running on this machine.
        if entity_type == "CIM_ComputerSystem":
            _add_default_scripts(grph, root_node, entity_id)

    _add_default_nodes(grph, root_node, entity_host)

    cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_directory, pc.property_script])

if __name__ == '__main__':
    Main()

