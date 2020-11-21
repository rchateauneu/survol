#!/usr/bin/env python

"""
Scripts hierarchy

It is used by entity.py as a module, but also as a script with the CGI parameter mode=menu,
by the D3 interface, to build contextual right-click menu.
It is also used by the client library lib_client, to return all the scripts accessible from an object.
It is never displayed directly.
"""

import os
import re
import sys
import lib_util
import lib_common
from lib_properties import pc

# TODO: When converted in RDF, the URL should use see_also, PredicateSeeAlso, RDFS.seeAlso


def _test_usability(imported_module, entity_type, entity_ids_arr):
    """
    This returns None if a module of a script is usable, otherwise an error message which explains
    why this script cannot be used in this context: Wrong platform, unavailable resources etc...
    """

    # PROBLEM: When an entire directory is not Usable because the file __init__.py
    # has a function Usable which returns False, then it still displays a directory, alone.
    # Unusable scripts are not displayed in the menu of the scripts of an entity,
    #except if a special flag is given, and in this case these error messages are displayed.
    try:
        is_usable = imported_module.Usable(entity_type, entity_ids_arr)
    except :
        return None

    # sys.stderr.write("Module %s : %d\n" %(importedMod.__name__,is_usable    ))
    if is_usable:
        return None

    error_msg = imported_module.Usable.__doc__
    if error_msg:
        error_msg = error_msg.strip()
    else:
        error_msg = imported_module.__name__
        if error_msg:
            error_msg += " not usable"
        else:
            error_msg = "No message"
    return error_msg


def _dir_menu_report(depth_call, str_msg):
    """For debugging purpose only."""
    txt_margin = "    " * depth_call
    DEBUG(txt_margin + str_msg)


# TODO: Only return json data, and this script will only return json, nothing else.
def DirToMenu(callback_grph_add, parent_node, entity_type, entity_id, entity_host, flag_show_all):

    def directory_usability_error_node(relative_dir, depthCall):
        # Maybe there is a usability test in the current module.
        # The goal is to control all scripts in the subdirectories, from here.
        try:
            entity_class = ".".join(relative_dir.split("/")[2:])
            #_dir_menu_report( depthCall, "entity_class=%s\n"%(entity_class))

            imported_module = lib_util.GetEntityModule(entity_class)
            if imported_module:
                error_msg = _test_usability(imported_module, entity_type, entity_ids_arr)
                # if flagShowAll and error_msg ???
                if error_msg:
                    DEBUG("IsDirectoryUsable error_msg(1)=%s" ,error_msg)
                    # If set to True, the directory is displayed even if all its scripts
                    # are not usable. Surprisingly, the message is not displayed as a subdirectory, but in a separate square.
                    return lib_util.NodeLiteral(error_msg)
        except IndexError:
            # If we are at the top-level, no interest for the module.
            pass

        return None


    def dir_to_menu_aux(a_parent_node, grand_parent_node, curr_dir, relative_dir, depth_call=1):
        """This lists the scripts and generate RDF nodes. Returns True if something was added."""

        #_dir_menu_report( depthCall, "curr_dir=%s relative_dir=%s\n"%(curr_dir,relative_dir))
        # In case there is nothing.
        dirs = None
        for path, dirs, files in os.walk(curr_dir):
            break

        # Maybe this class is not defined in our ontology.
        if dirs == None:
            WARNING("dir_to_menu_aux(2) No content in %s", curr_dir)
            return False

        # Will still be None if nothing is added.
        rdf_node = None
        sub_path = path[len(curr_dir):]

        relative_dir_sub_path = relative_dir + sub_path

        arg_dir = relative_dir_sub_path.replace("/", ".")[1:]

        # If this is a remote host, all scripts are checked because they might have
        # the flag CanProcessRemote which is defined at the script level, not the directory level.
        if not entity_host:
            err_dir_node = directory_usability_error_node(relative_dir, depth_call)
            if err_dir_node:
                if flag_show_all:
                    arg_dir_split = arg_dir.split(".")
                    curr_dir_node = lib_util.DirDocNode(".".join(arg_dir_split[:-1]), arg_dir_split[-1])
                    if not curr_dir_node:
                        curr_dir_node = lib_util.NodeLiteral("Cannot parse relative dir:%s" % arg_dir)
                    callback_grph_add((grand_parent_node, pc.property_script, curr_dir_node), depth_call)
                    callback_grph_add((curr_dir_node, lib_common.MakeProp("Error"), err_dir_node), depth_call)
                # The directory is not usable, so leave immediately.
                return False

        contains_something = False
        for dir in dirs:
            #_dir_menu_report( depthCall, "dir=%s\n"%(dir))
            # Might be generated by our Python interpreter.
            if dir == "__pycache__":
                continue

            full_sub_dir = os.path.join(curr_dir, dir)

            curr_dir_node = lib_util.DirDocNode(arg_dir, dir)

            if not curr_dir_node:
                #_dir_menu_report( depthCall, "curr_dir_node NONE: arg_dir=%s dir=%s\n"%(arg_dir,dir))
                continue

            sub_relative_dir = relative_dir + "/" + dir

            sub_entity_class = ".".join( sub_relative_dir.split("/")[2:] )
            onto_keys = lib_util.OntologyClassKeys(sub_entity_class)
            #_dir_menu_report( depthCall, "Checked ontology of %s: onto_keys=%s\n"%(sub_entity_class,str(onto_keys)))

            # TODO: Beware, if not ontology, returns empty array. Why not returning None ?
            if onto_keys != []:
                #_dir_menu_report( depthCall, "Module %s has an ontology so it is a class. Skipping\n"%(sub_relative_dir))
                # BEWARE: NO MORE DEFAULT ONTOLOGY ["Id"]
                continue

            something_added = dir_to_menu_aux(curr_dir_node, a_parent_node, full_sub_dir, sub_relative_dir, depth_call + 1)
            # This adds the directory name only if it contains a script.
            if something_added:
                # It works both ways, possibly with different properties.
                callback_grph_add((a_parent_node, pc.property_script, curr_dir_node), depth_call)
            contains_something = contains_something | something_added

        for fil in files:
            # We want to list only the usable Python scripts.
            if not fil.endswith(".py") or fil == "__init__.py":
                continue

            script_path = relative_dir_sub_path + "/" + fil

            #_dir_menu_report( depthCall, "DirToMenu encoded_entity_id=%s\n" % encoded_entity_id)

            url_rdf = genObj.MakeTheNodeFromScript(script_path, entity_type, encoded_entity_id)

            error_msg = None

            try:
                imported_mod = lib_util.GetScriptModule(arg_dir, fil)
            except Exception as exc:
                error_msg = exc
                #_dir_menu_report( depthCall, "dir_to_menu_aux Cannot import=%s. Caught: %s\n" % (script_path, error_msg ) )
                imported_mod = None
                if not flag_show_all:
                    continue

            if not error_msg:
                # Show only scripts which want to be shown. Each script can have an optional function
                # called Usable(): If it is there and returns False, the script is not displayed.
                error_msg = _test_usability(imported_mod, entity_type, entity_ids_arr)
                if error_msg:
                    pass
                    #DEBUG("dir_to_menu_aux error_msg(2)=%s",error_msg)

            # If this is a local host
            if not flag_show_all and error_msg and not entity_host:
                continue

            # If the entity is on another host, does the script run on remote entities ?
            # The concept of "CanProcessRemote" is a short-hand to avoid checking
            # if the remote is in the entity ids. This flag means:
            # "It is worth anyway investigating on a remote host, if the entity exists there."
            if entity_host:
                try:
                    # Script can be used on a remote entity.
                    can_process_remote = imported_mod.CanProcessRemote
                except AttributeError:
                    can_process_remote = False

                if not can_process_remote:
                    if not error_msg:
                        error_msg = "%s is local" % entity_host

                    if not flag_show_all:
                        continue
                else:
                    _dir_menu_report(depth_call, "Script %s %s CAN work on remote entities\n" % (arg_dir, fil))

            # Here, we are sure that the script is added.
            # TODO: If no script is added, should not add the directory?
            rdf_node = lib_common.NodeUrl(url_rdf)
            callback_grph_add((a_parent_node, pc.property_script, rdf_node), depth_call)

            # Default doc text is file name minus the ".py" extension.
            nod_modu = lib_util.FromModuleToDoc(imported_mod, fil[:-3])

            callback_grph_add((rdf_node, pc.property_information, nod_modu), depth_call)

            if error_msg:
                callback_grph_add((rdf_node, lib_common.MakeProp("Error"), lib_util.NodeLiteral(error_msg)), depth_call)

        # This tells if a script was added in this directory or one of the subdirs.
        return (rdf_node is not None) | contains_something

    if entity_host:
        DEBUG("entity_dir_menu.py DirToMenu entity_host=%s",entity_host)
    encoded_entity_id = lib_util.EncodeUri(entity_id)
    entity_ids_arr = lib_util.EntityIdToArray(entity_type, entity_id)

    if entity_type:
        # entity_type might contain a slash, for example: "sqlite/table"
        relative_dir = "/sources_types/" + entity_type
    else:
        relative_dir = "/sources_types"

    directory = lib_util.gblTopScripts + relative_dir

    if entity_host:
        genObj = lib_common.RemoteBox(entity_host)
    else:
        genObj = lib_common.gUriGen

    dir_to_menu_aux(parent_node, None, directory, relative_dir, depth_call=1)


def Main():
    # This can process remote hosts because it does not call any script, just shows them.
    cgiEnv = lib_common.CgiEnv(
                    can_process_remote=True,
                    parameters={lib_util.paramkeyShowAll : False})
    entity_id = cgiEnv.m_entity_id
    entity_host = cgiEnv.GetHost()
    flag_show_all = int(cgiEnv.get_parameters(lib_util.paramkeyShowAll))

    name_space, entity_type = cgiEnv.get_namespace_type()

    if lib_util.IsLocalAddress(entity_host):
        entity_host = ""

    DEBUG("entity: entity_host=%s entity_type=%s entity_id=%s", entity_host, entity_type, entity_id )

    grph = cgiEnv.GetGraph()

    root_node = lib_util.RootUri()

    if entity_id != "" or entity_type == "":
        def callback_grph_add(tripl, depth_call):
            grph.add(tripl)

        DirToMenu(callback_grph_add, root_node, entity_type, entity_id, entity_host, flag_show_all)

    cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_directory, pc.property_script])


if __name__ == '__main__':
    Main()

