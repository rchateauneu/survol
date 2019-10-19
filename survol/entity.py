#!/usr/bin/env python

"""
Overview
"""

import os
import re
import sys
import lib_util
import lib_common
from lib_properties import pc

# This script is also used as a module.
import entity_dirmenu_only # Also used with the CGI parameter mode=menu


##### import entity_info_only # Also used with the CGI parameter mode=json
## WE SHOULD NOT LOAD USELESS STUFF WHEN WE WANT TO DISPLAY ONLY THE NODES IN THE D3 INTERFACE.
## AND THE LINKS LIKE WBEM OR WMI SHOULD BE PROPERLY DISPLAYED.
## IN THE CONTEXTUAL MENU ??

from sources_types import CIM_Process
FunctionGetUser = CIM_Process.GetCurrentUser

from sources_types import CIM_ComputerSystem

################################################################################

def AddDefaultNodes(grph,rootNode,entity_host):
    DEBUG("entity.py AddDefaultNodes entity_host=%s",entity_host)
    currentNodeHostname = lib_common.gUriGen.HostnameUri( lib_util.currentHostname )
    grph.add( ( currentNodeHostname, pc.property_information, lib_common.NodeLiteral("Current host:"+lib_util.currentHostname) ) )
    grph.add( ( rootNode, pc.property_rdf_data_nolist2, currentNodeHostname ) )

    currUsername = FunctionGetUser()
    currentNodeUser = lib_common.gUriGen.UserUri( currUsername )
    grph.add( ( currentNodeUser, pc.property_information, lib_common.NodeLiteral("Current user:"+currUsername) ) )
    grph.add( ( rootNode, pc.property_rdf_data_nolist2, currentNodeUser ) )

# TODO: Maybe the property should be property_script ??
def AddDefaultScripts(grph,rootNode,entity_host):
    DEBUG("entity.py AddDefaultScripts entity_host=%s",entity_host)
    nodeObjTypes = lib_common.NodeUrl( lib_util.uriRoot + '/objtypes.py' )
    grph.add( ( rootNode, pc.property_rdf_data_nolist2, nodeObjTypes ) )

    # Gives a general access to WBEM servers. In fact we might iterate on several servers, or none.
    nodePortalWbem = lib_util.UrlPortalWbem(entity_host)
    grph.add( ( rootNode, pc.property_rdf_data_nolist2, nodePortalWbem ) )

    # Gives a general access to WMI servers.
    nodePortalWmi = lib_util.UrlPortalWmi(entity_host)
    grph.add( ( rootNode, pc.property_rdf_data_nolist2, nodePortalWmi ) )


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
                    can_process_remote = True,
                    parameters = { lib_util.paramkeyShowAll : False })
    entity_id = cgiEnv.m_entity_id
    entity_host = cgiEnv.GetHost()
    DEBUG("entity_host=%s",entity_host)
    flagShowAll = int(cgiEnv.GetParameters( lib_util.paramkeyShowAll ))

    ( nameSpace, entity_type, entity_namespace_type ) = cgiEnv.GetNamespaceType()

    grph = cgiEnv.GetGraph()

    rootNode = lib_util.RootUri()
    DEBUG("rootNode=%s",rootNode)

    entity_ids_arr = lib_util.EntityIdToArray( entity_type, entity_id )
    # entity_info_only.AddInformation(grph,rootNode,entity_id, entity_type)

    # Each entity type ("process","file" etc... ) can have a small library
    # of its own, for displaying a rdf node of this type.
    if entity_type:
        entity_module = lib_util.GetEntityModule(entity_type)
        if entity_module:
            try:
                entity_module.AddInfo( grph, rootNode, entity_ids_arr )
            except AttributeError as exc:
                INFO("entity.py No AddInfo for %s %s: %s", entity_type, entity_id, str(exc) )
            except Exception as exc:
                INFO("entity.py Unexpected exception for %s %s: %s", entity_type, entity_id, str(exc) )
    else:
        INFO("No lib_entities for %s %s", entity_type, entity_id )

    # When displaying in json mode, the scripts are shown with a contextual menu, not with D3 modes..
    if lib_util.GuessDisplayMode() not in ["json","html"]:

        # This function is called for each script which applies to the given entity.
        # It receives a triplet: (subject,property,object) and the depth in the tree.
        # Here, this simply stores the scripts in a graph. The depth is not used yet,
        # but can help debugging.
        def CallbackGrphAdd( tripl, depthCall ):
            try:
                grph.add(tripl)
            except Exception as exc:
                ERROR("CallbackGrphAdd: tripl=%s exception=%s" % (str(tripl), str(exc)))
                raise

        try:
            entity_dirmenu_only.DirToMenu(CallbackGrphAdd,rootNode,entity_type,entity_id,entity_host,flagShowAll)
        except Exception as exc:
            ERROR("entity.py caught in ForToMenu:%s", exc)

        # This adds WBEM and WMI urls related to the current object.
        if entity_type != "":
            CIM_ComputerSystem.AddWbemWmiServers(grph,rootNode, entity_host, nameSpace, entity_type, entity_id)

        AddDefaultScripts(grph,rootNode,entity_host)

        # Special case if the currententity we are displaying, is a machine,
        # we might as well try to connect to its WMI or WBEM server, running on this machine.
        if entity_type == "CIM_ComputerSystem":
            AddDefaultScripts(grph,rootNode,entity_id)

    AddDefaultNodes(grph,rootNode,entity_host)

    cgiEnv.OutCgiRdf( "LAYOUT_RECT", [pc.property_directory,pc.property_script])

if __name__ == '__main__':
    Main()

