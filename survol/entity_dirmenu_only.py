#!/usr/bin/env python

"""
Scripts hierarchy

It is used by entity.py as a module, but also as a script with the CGI parameter mode=menu,
by the D3 interface, to build contextual right-click menu.
It is also used by the client library lib_client, to return all the scripts accessible from an object.
It is never displayed directly.
"""

import os
import sys
import logging

import lib_util
import lib_common
import lib_dirmenu
from lib_properties import pc

def Main():
    # This can process remote hosts because it does not call any script, just shows them.
    cgiEnv = lib_common.ScriptEnvironment(
                    can_process_remote=True,
                    parameters={lib_util.paramkeyShowAll: False})
    entity_id = cgiEnv.m_entity_id
    entity_host = cgiEnv.GetHost()
    flag_show_all = int(cgiEnv.get_parameters(lib_util.paramkeyShowAll))

    name_space, entity_type = cgiEnv.get_namespace_type()

    if lib_util.is_local_address(entity_host):
        entity_host = ""

    logging.debug("entity: entity_host=%s entity_type=%s entity_id=%s", entity_host, entity_type, entity_id)

    grph = cgiEnv.GetGraph()

    root_node = lib_util.RootUri()

    if entity_id != "" or entity_type == "":
        def callback_grph_add(tripl, depth_call):
            grph.add(tripl)

        lib_dirmenu.recursive_walk_on_scripts(
            callback_grph_add, root_node, entity_type, entity_id, entity_host, flag_show_all)

    # J ai l'impresson que ca n'est utilise que en "json" donc pas besoin de "mode=menu" ???
    # VERIFIONS !
    # Faut le splitter entre lib_dirmenu.py d'une part
    # et d'autre part ce script qui va ne renvoyer ses infos que en json en pratique.
    # Probleme : Le RDF qu'on fabrique n'est pas adapte a fabriquer les menus JSON,
    # Aussi: On a duplique les fonctions dans entity_menu_seealso.
    # Donc : entity_menu_seealso va utilise aussi lib_dirmenu
    cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_directory, pc.property_script])


if __name__ == '__main__':
    Main()

