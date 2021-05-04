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

import lib_uris
import lib_util
import lib_common
import lib_naming
import lib_ontology_tools
from lib_properties import pc

try:
    import lib_wmi
except ImportError:
    lib_wmi = None

try:
    import lib_wbem
except ImportError:
    lib_wbem = None

# TODO: When converted in RDF, the URL should use see_also, PredicateSeeAlso, RDFS.seeAlso


def _add_cim_links(callback_grph_add, parent_node, entity_type, entity_id, gen_obj):
    # This does not take into account WBEM running on Windows, or WMI on Linux, because this is not realistic.
    if lib_wmi:
        _add_wmi_links(callback_grph_add, parent_node, entity_type, entity_id, gen_obj)
    if lib_wbem:
        _add_wbem_links(callback_grph_add, parent_node, entity_type, entity_id, gen_obj)


def _add_wmi_links(callback_grph_add, parent_node, entity_type, entity_id, gen_obj):

    """
    wmi_associators_list(entity_type, entity_id) = ["ASSOC1", "ASSOC2"]

    This applies only if this class is defined in WMI or WBEM respectively, as Survol classes have no associators.

    # This creates a menu like:
    # "WMI associators" =>

    :param callback_grph_add:
    :param parent_node:
    :param entity_type:
    :param entity_id:
    :return:
    """

    # Get the list of associators names and field names, from the ontology, in WMI or WBEM.
    # It is possible to have both types of accessors, or none.

    # From survol_ontology_attributes.wmi.202104.json
    # CIM_ProcessExecutable.Antecedent
    #                    predicate_type	"ref:CIM_DataFile"
    #                    predicate_domai ["CIM_Process"]
    # CIM_ProcessExecutable.Dependent
    #                    predicate_type	"ref:CIM_Process"
    #                    predicate_domain ["CIM_DataFile"]

    # Get the list of attributes, like "accessor name.field name" which have a predicate type of the given class.
    # See terminology: https://docs.microsoft.com/en-us/windows/win32/wmisdk/associators-of-statement
    # ASSOCIATORS OF {ObjectPath} WHERE
    #     AssocClass = AssocClassName
    #     ClassDefsOnly
    #     RequiredAssocQualifier = QualifierName
    #     RequiredQualifier = QualifierName
    #     ResultClass = ClassName
    #     ResultRole = PropertyName
    #     Role = PropertyName
    # For each of these attributes, create a URL like:
    # associators_wmi.py?xid=<the-xid>&__result_class__=<class name>&__result_role__=<xyz>

    logging.debug("entity_type=%s entity_id=%s", entity_type, entity_id)
    depth_call = 1
    wmi_associators_node = None

    attributes_list = lib_ontology_tools.class_associators("wmi", lib_wmi.extract_specific_ontology_wmi, entity_type)
    for attribute_name in attributes_list:
        logging.debug("attribute_name=%s", attribute_name)
        # It must have the syntax "associator.role"
        assert attribute_name.find(".") > 0
        if wmi_associators_node is None:
            # Add the parent node only if there is at least one associator.
            wmi_associators_node = lib_util.NodeLiteral("WMI associators")
            callback_grph_add((parent_node, pc.property_script, wmi_associators_node), depth_call)

        # The CGI parameter "xid" is normally the only CGI parameter related to data.
        # Extra CGI parameters are used for display mode (RDF, SVG etc...) or for parameters edition,
        # that is, for "technical" things.
        # Here, this is the only place where an extra CGI parameters related to data is used.
        # This is why no function is created in lib_urls for this purpose.
        # This might change if, in the future, all parameters of the instances are passed
        # as plain CGI parameters, like the technical parameters which will be prefixed and suffixed with "__".
        # url_path = gen_obj.create_entity_path("/entity.py", entity_type, entity_id.replace("/", ""))
        url_path = gen_obj.create_entity_path("/entity.py", entity_type, entity_id)
        url_path += "&amp;__associator_attribute__=" + attribute_name
        script_node = lib_util.NodeUrl(url_path)

        associator_name, _, _ = attribute_name.partition(".")
        callback_grph_add((wmi_associators_node, pc.property_script, script_node), depth_call + 1)
        script_label, _, _ = lib_naming.ParseEntityUri(url_path)
        callback_grph_add((script_node, pc.property_information, lib_util.NodeLiteral(script_label)), depth_call + 1)

    # TODO: It is possible to enumerate all objects of a given class.
    # TODO: However, it might return too many objects, and it is not possible to set the field values,
    # TODO: so it is a poor usage of SELECT query.
    # TODO: Therefore it is much better to have a form for entering values for each field.
    # add_enumeration_of_objects_of_this_class(parent_node)


def _add_wbem_links(callback_grph_add, parent_node, entity_type, entity_id, gen_obj):
    logging.warning("entity_type=%s entity_id=%s wbem not implemented yet", entity_type, entity_id)


def _test_usability(imported_module, entity_type, entity_ids_arr):
    """
    This returns None if a module of a script is usable, otherwise an error message which explains
    why this script cannot be used in this context: Wrong platform, unavailable resources etc...
    """

    # PROBLEM: When an entire directory is not Usable because the file __init__.py
    # has a function Usable which returns False, then it still displays a directory, alone.
    # Unusable scripts are not displayed in the menu of the scripts of an entity,
    # except if a special flag is given, and in this case these error messages are displayed.
    try:
        is_usable = imported_module.Usable(entity_type, entity_ids_arr)
    except AttributeError as exc:
        logging.info("entity_type=%s entity_ids_arr=%s module %s has no Usable attribute: Caught %s",
                        entity_type, str(entity_ids_arr), imported_module.__name__, exc)
        return None
    except Exception as exc:
        logging.error("entity_type=%s entity_ids_arr=%s module %s: Caught %s",
                        entity_type, str(entity_ids_arr), imported_module.__name__, exc)
        return None

    if is_usable:
        return None

    error_msg = imported_module.Usable.__doc__
    if error_msg:
        error_msg = error_msg.strip()
        # Just take the first line of __doc__ string.
        error_msg = error_msg.split("\n")[0]
    else:
        error_msg = imported_module.__name__
        if error_msg:
            error_msg += " not usable"
        else:
            error_msg = "No message"
    return error_msg


# TODO: Only return json data, and this script will only return json, nothing else.
def recursive_walk_on_scripts(callback_grph_add, parent_node, entity_type, entity_id, entity_host, flag_show_all):
    """
    This adds to a RDF graph the tree of scripts which can be applied to an object (sometimes called entity)
    defined by its class and the values of its attributes.
    If the class is not defined, then it is a top-level script.
    Scripts are defined by a RDF node: The URL contains the script and the arguments.

    :param callback_grph_add: The graph to which the scripts are added.
    :param parent_node:
    :param entity_type:
    :param entity_id:
    :param entity_host:
    :param flag_show_all: If True, disabled scripts are also returned.
    :return:
    """

    # This is used when disabled script as returned.
    script_error_property = lib_common.MakeProp("Script error")

    def directory_usability_error_node(relative_dir, depth_call):
        # Maybe there is a usability test in the current module.
        # The goal is to control all scripts in the subdirectories, from here.
        try:
            entity_class = ".".join(relative_dir.split("/")[2:])

            imported_module = lib_util.GetEntityModule(entity_class)
            if imported_module:
                error_msg = _test_usability(imported_module, entity_type, entity_ids_arr)
                if error_msg:
                    # If set to True, the directory is displayed even if all its script are not usable.
                    return lib_util.NodeLiteral(error_msg)
        except IndexError:
            # If we are at the top-level, no interest for the module.
            pass

        return None

    def recursive_walk_aux(a_parent_node, grand_parent_node, curr_dir, relative_dir, depth_call=1):
        """This lists the scripts and generate RDF nodes. Returns True if something was added."""

        # In case there is nothing.
        dirs = None
        for path, dirs, files in os.walk(curr_dir):
            break

        # Maybe this class is not defined in our ontology.
        if dirs == None:
            logging.warning("dir_to_menu_aux(2) No content in %s", curr_dir)
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
                    callback_grph_add((curr_dir_node, script_error_property, err_dir_node), depth_call)
                # The directory is not usable, so leave immediately.
                return False

        contains_something = False
        for dir in dirs:
            # This directory may be generated by our Python interpreter.
            if dir == "__pycache__":
                continue

            full_sub_dir = os.path.join(curr_dir, dir)

            try:
                curr_dir_node = lib_util.DirDocNode(arg_dir, dir)
            except Exception as exc:
                logging.error("exc=%s", exc)
                raise

            if not curr_dir_node:
                logging.warning("curr_dir_node is None: arg_dir=%s dir=%s", arg_dir, dir)
                continue

            sub_relative_dir = relative_dir + "/" + dir

            sub_entity_class = ".".join(sub_relative_dir.split("/")[2:])
            onto_keys = lib_util.OntologyClassKeys(sub_entity_class)

            # TODO: Beware, if not ontology, returns empty array. Why not returning None ?
            if onto_keys != []:
                # Maybe this is a subclass with its own ontology.
                # So its scripts do not apply to the current class.
                logging.info("sub_entity_class=%s onto_keys=%s", sub_entity_class, onto_keys)
                continue

            something_added = recursive_walk_aux(
                curr_dir_node, a_parent_node, full_sub_dir, sub_relative_dir, depth_call + 1)
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

            rdf_node = gen_obj.MakeTheNodeFromScript(script_path, entity_type, encoded_entity_id)

            error_msg = None

            try:
                imported_mod = lib_util.GetScriptModule(arg_dir, fil)
            except Exception as exc:
                logging.warning("Caught:%s", exc)
                error_msg = exc
                imported_mod = None
                if not flag_show_all:
                    continue

            if not error_msg:
                # Show only scripts which want to be shown. Each script can have an optional function
                # called Usable(): If it is there and returns False, the script is not displayed.
                error_msg = _test_usability(imported_mod, entity_type, entity_ids_arr)
                if error_msg:
                    pass

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
                    logging.debug("Script %s %s CAN work on remote entities", arg_dir, fil)

            # Here, we are sure that the script is added.
            # TODO: If no script is added, should not add the directory?
            callback_grph_add((a_parent_node, pc.property_script, rdf_node), depth_call)

            # Default doc text is file name minus the ".py" extension.
            nod_modu = lib_util.module_doc_string(imported_mod, fil[:-3])

            # nod_modu contains a literal of a str.
            if not isinstance(nod_modu, str):
                logging.error("nod_modu=%s should be str instead of %s", nod_modu, type(nod_modu))

            callback_grph_add((rdf_node, pc.property_information, nod_modu), depth_call)

            if error_msg:
                callback_grph_add((rdf_node, script_error_property, lib_util.NodeLiteral(error_msg)), depth_call)

        # This tells if a script was added in this directory or one of the subdirs.
        return (rdf_node is not None) | contains_something

    if entity_host:
        logging.debug("entity_host=%s", entity_host)
    # This will not be needed anymore when MakeTheNodeFromScript properly encode chars like UriMakeFromDict.
    # TODO: Use base64 for urls, everywhere. Use appropriate encoding for XML, SVG or HTML text.
    encoded_entity_id = lib_util.EncodeUri(entity_id)
    entity_ids_arr = lib_util.EntityIdToArray(entity_type, entity_id)

    if entity_type:
        # entity_type might contain a slash, for example: "sqlite/table"
        relative_dir = "/sources_types/" + entity_type
    else:
        relative_dir = "/sources_types"

    directory = lib_util.gblTopScripts + relative_dir

    gen_obj = lib_uris.MachineBox(entity_host)

    recursive_walk_aux(parent_node, None, directory, relative_dir, depth_call=1)

    if entity_type:
        _add_cim_links(callback_grph_add, parent_node, entity_type, entity_id, gen_obj)


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

        recursive_walk_on_scripts(callback_grph_add, root_node, entity_type, entity_id, entity_host, flag_show_all)

    cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_directory, pc.property_script])


if __name__ == '__main__':
    Main()

