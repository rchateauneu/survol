import lib_util
import lib_mime
import sys
import os
import re
import lib_patterns


def _entity_array_to_label(entity_type, entity_ids_arr):
    """This fetches in the module of the class, a function called "EntityName"."""
    func_entity_name = lib_util.HierarchicalFunctionSearch(entity_type, "EntityName")

    if func_entity_name:
        entity_name = func_entity_name(entity_ids_arr)
        return entity_name

    # General case of a URI created by us and for us.
    ent_ids_joined = ",".join(entity_ids_arr)
    if lib_patterns.TypeToGraphParams(entity_type) is None:
        # If the type does not have a special color, add its name.
        return "%s (%s)" % (ent_ids_joined, entity_type)
    else:
        return ent_ids_joined


def _entity_array_to_alias(entity_type, entity_ids_arr, force_entity_ip_addr):
    """This calls for an object, the class-specific function UniversalAlias, if it exists.
    Otherwise, it generates a default string with the object's parameters.
    The universal alias of an object is the same for all Survol agents no matter what
    the host they are running on, or their URL.
    Therefore, if several agents are running on the same machine but are hosted differently
    (Apache, IIS, cgiserver.py script running with different accounts and different port numbers),
    they will calculate the same universal alias for the same objects, even if
    the URLs are different.
    """

    func_universal_alias = lib_util.HierarchicalFunctionSearch(entity_type, "UniversalAlias")

    if func_universal_alias:
        univ_alias = func_universal_alias(entity_ids_arr, force_entity_ip_addr, entity_type)
    else:
        # The default alias must contain the class name otherwise there could be an ambiguity
        # between objects of different classes, on the same machine with the attributes values.
        ent_ids_joined = ",".join(entity_ids_arr)

        # This adds a hostname to the moniker, with the Survol syntax.
        # But maybe this object will be described by WBEM or WMI.
        univ_alias = "%s@%s:%s" % (force_entity_ip_addr, entity_type, ent_ids_joined)

    return univ_alias


def EntityToLabel(entity_type, entity_ids_concat, force_entity_ip_addr):
    """
    This returns the label of an URL which is a script plus CGI arguments defining an object.

    For an association, we might have:
    entity_id=Dependent=root/cimv2:LMI_StorageExtent.CreationClassName="LMI_StorageExtent",SystemCreationClassName="PG_ComputerSystem" Antecedent=root/cimv2:LMI_DiskDrive.CreationClassName="LMI_DiskDrive",DeviceID="/dev/sda"
    This is not easy to manage but avoids ambiguities.
    """
    #sys.stderr.write("EntityToLabel entity_id=%s entity_type=%s\n" % ( entity_ids_concat, entity_type ) )

    # Specific case of objtypes.py
    if not entity_ids_concat:
        return entity_type

    # TODO: Robust logic as long as the value does not contain an '=' sign.
    split_kv = lib_util.SplitMoniker(entity_ids_concat)

    # Now build the array of values in the ontology order.
    onto_keys = lib_util.OntologyClassKeys(entity_type)

    # Default value if key is missing.
    entity_ids_arr = [split_kv.get(key_onto, key_onto + "?") for key_onto in onto_keys]

    if force_entity_ip_addr:
        entity_label = _entity_array_to_alias(entity_type, entity_ids_arr, force_entity_ip_addr)
    else:
        entity_label = _entity_array_to_label(entity_type, entity_ids_arr)
    # sys.stderr.write("EntityToLabel entity_label=%s\n" % entity_label )

    # There might be extra properties which are not in our ontology.
    # This happens if duplicates from WBEM or WMI. MAKE THIS FASTER ?
    # Both must be sets, otherwise unsupported operation.

    # TODO: This set could be created once and for all. But the original order must be kept.
    set_onto_keys = set(onto_keys)

    # This appends the keys which are not part of the normal ontology, therefore bring extra information.
    # This is rather slow and should normally not happen.
    for ext_prp_key, ext_prp_val in split_kv.items():
        if not ext_prp_key in set_onto_keys:
            entity_label += " %s=%s" % (ext_prp_key, ext_prp_val)

    return entity_label


# This is used to display a clean title for some specific scripts.
# TODO: Consider using the "__doc__" string in each file.
_scripts_to_titles = {
    "portal_wbem.py": "WBEM server ",
    "portal_wmi.py": "WMI server ",
    "class_wbem.py": "WBEM class",
    "class_wmi.py": "WMI class",
    # "class_type_all.py": "Generic class",
    "file_directory.py": "Directory content",
    "objtypes.py": "Classes hierarchy",
    "objtypes_wbem.py": "WBEM subclasses",
    "objtypes_wmi.py": "WMI subclasses",
    "namespaces_wbem.py": "WBEM namespaces",
    "namespaces_wmi.py": "WMI namespaces",
    "entity.py": "",
    "entity_wbem.py": "WBEM",
    "entity_wmi.py": "WMI",
}


def _known_script_to_title(fil_script, uri_mode, entity_host=None, entity_suffix=None):
    """Extra information depending on the script."""

    # Special display if MIME URL
    if fil_script == "entity_mime.py":
        if not entity_suffix:
            entity_suffix = "None"
        # The Mime type is embedded into the mode, after a "mime:" prefix.
        entity_label = entity_suffix + " (" + lib_mime.ModeToMimeType(uri_mode) + ")"
        return entity_label

    # The label is a Survol module name which is a class (With an EntityOntology() function),
    #  or a namespace. So we give the right title.
    if fil_script == "class_type_all.py":
        moduOntology = lib_util.OntologyClassKeys(entity_suffix)
        if moduOntology:
            entity_label = entity_suffix + " (Class)"
        else:
            entity_label = entity_suffix + " (Domain)"
        return entity_label

    try:
        entity_label = _scripts_to_titles[fil_script]
    except KeyError:
        entity_label = fil_script + "..."

    if entity_suffix:
        if entity_label:
            entity_label = entity_suffix + " (" + entity_label + ")"
        else:
            entity_label = entity_suffix

    # Maybe hostname is a CIMOM address (For WBEM) or a machine name.
    if entity_host:
        if not lib_util.IsLocalAddress(entity_host):
            # If this is a CIMOM, make it shorter: "http://vps516494.ovh.net:5988" or ""https://vps516494.ovh.net:5989"
            host_only = lib_util.EntHostToIp(entity_host)
            entity_label += " at " + host_only

    # TODO: Add the host name in the title.
    return entity_label


def _calc_label(entity_host, entity_type, entity_id, force_entity_ip_addr, fil_script):
    nam_spac, entity_type_no_ns = lib_util.parse_namespace_type(entity_type)

    if not force_entity_ip_addr and not lib_util.IsLocalAddress(entity_host):
        entity_label = None
        if fil_script == "entity_wbem.py":
            import lib_wbem
            # Because of WBEM, entity_host is a CIMOM url, like "http://vps516494.ovh.net:5988"
            entity_label = lib_wbem.EntityToLabelWbem(nam_spac, entity_type_no_ns, entity_id, entity_host)
            if not entity_label:
                # Fallback to Survol label.
                actual_host = lib_util.EntHostToIp(entity_host)

                entity_label = EntityToLabel(entity_type_no_ns, entity_id, actual_host)
        elif fil_script == "entity_wmi.py":
            import lib_wmi
            # For WMI, the hostname is a NETBIOS machine name.
            entity_label = lib_wmi.EntityToLabelWmi(nam_spac, entity_type_no_ns, entity_id, entity_host)
            if not entity_label:
                # Fallback to Survol label.
                actual_host = lib_util.EntHostToIp(entity_host)
                entity_label = EntityToLabel(entity_type_no_ns, entity_id, actual_host)
        else:
            # filScript in [ "class_type_all.py", "entity.py" ], or if no result from WMI or WBEM.
            entity_label = EntityToLabel(entity_type_no_ns, entity_id, entity_host)

    elif entity_type_no_ns or entity_id:
        entity_label = EntityToLabel(entity_type_no_ns, entity_id, force_entity_ip_addr)
    else:
        # Only possibility to print something meaningful.
        entity_label = nam_spac

    # Some corner cases: "http://127.0.0.1/Survol/survol/entity.py?xid=CIM_ComputerSystem.Name="
    if not entity_label:
        entity_label = entity_type

    return entity_label


def ParseEntityUriWithHost(uri_with_mode, long_display=True, force_entity_ip_addr=None):
    """Extracts the entity type and id from a URI, coming from a RDF document.
    This is used notably when transforming RDF into dot documents.
    The returned entity type is used for choosing graphic attributes
    and gives more information than the simple entity type.

    Example:
    (labText, entity_graphic_class, entity_id) = lib_naming.ParseEntityUri(the_url)
    """
    #sys.stderr.write("ParseEntityUri uri_with_mode=%s\n"%uri_with_mode)

    # Maybe there is a host name before the entity type. It can contain letters, numbers,
    # hyphens, dots etc... but no ":" or "@".
    # THIS CANNOT WORK WITH IPV6 ADDRESSES...
    # WE MAY USE SCP SYNTAX: scp -6 osis@\[2001:db8:0:1\]:/home/osis/test.file ./test.file

    # This conversion because it might be called with rdflib.term.URIRef
    if not isinstance(uri_with_mode, str):
        uri_with_mode = str(uri_with_mode)

    # This replaces "&amp;" by "&" up to two times if needed.
    uri_with_mode_clean = lib_util.UrlNoAmp(uri_with_mode)

    uprs = lib_util.survol_urlparse(uri_with_mode_clean)

    uprs_query = uprs.query
    uprs_query_split_cgi = uprs_query.split("&")
    cgi_arg_xid = None
    uri_mode = ""
    for one_cgi_arg in uprs_query_split_cgi:
        if one_cgi_arg.startswith("xid="):
            cgi_arg_xid = one_cgi_arg[4:]
        elif one_cgi_arg.startswith("mode="):
            uri_mode = one_cgi_arg[5:]

    # Default value.
    entity_host = ""

    fil_script = os.path.basename(uprs.path)

    # This works for the scripts:
    # entity.py            xid=namespace/type:idGetNamespaceType
    # objtypes_wbem.py     Just extracts the namespace, as it prefixes the type: xid=namespace/type:id

    # See variable lib_util.xidCgiDelimiter="?xid="
    # Possibly, the "xid" parameter does not come at the beginning.
    # Only the first "=" delimiter counts for the CGI variable.
    # if uprs.query.startswith("xid="):
    if cgi_arg_xid is not None:
        # TODO: Maybe the chain contains HTML codes and therefore cannot be parsed.
        # Ex: "xid=%40%2F%3Aoracle_package." == "xid=@/:oracle_package."
        # entity_type, entity_id, entity_host = lib_util.ParseXid(uprs.query[4:])
        entity_type, entity_id, entity_host = lib_util.ParseXid(cgi_arg_xid)

        entity_graphic_class = entity_type

        entity_label = _calc_label(entity_host, entity_type, entity_id, force_entity_ip_addr, fil_script)

        # TODO: Consider external_url_to_title, similar logic with different results.
        if long_display:
            entity_label = _known_script_to_title(fil_script, uri_mode, entity_host, entity_label)

    # Maybe an internal script, but not entity.py
    # It has a special entity type as a display parameter
    elif uri_with_mode_clean.startswith(lib_util.uriRoot):
        # This is a bit of a special case which allows to display something if we know only
        # the type of the entity but its id is undefined. Instead of displaying nothing,
        # this attempts to display all available entities of this given type.
        # source_top/enumerate_process.py etc... Not "." because this has a special role in Python.
        mtch_enumerate = re.match(r"^.*/enumerate_([a-z0-9A-Z_]*)\.py$", uri_with_mode_clean)
        if mtch_enumerate:
            entity_graphic_class = mtch_enumerate.group(1)
            entity_id = ""
            # TODO: Change this label, not very nice.
            # This indicates that a specific script can list all objects of a given entity type.
            entity_label = entity_graphic_class + " enumeration"
        else:
            entity_graphic_class = "provider_script"
            entity_id = ""
            entity_label = _known_script_to_title(fil_script, uri_mode)
    elif uri_with_mode_clean.split(':')[0] in ["ftp", "http", "https", "urn", "mail"]:
        # Standard URLs. Example: lib_common.NodeUrl( "http://www.google.com" )
        entity_graphic_class = ""
        entity_id = ""
        # Display the complete URL, otherwise it is not clickable.
        entity_label = uri_with_mode
    else:
        entity_graphic_class = ""
        # This specific keyword used when no class is specified and there is no object. It is easy to spot.
        # It happens for example for blank nodes, BNode, used to created literal values with a key:
        # Arguments of a function, successive values with a time-stamp.
        entity_id = "PLAINTEXTONLY"

        # Maybe an external URI sending data in RDF, HTML etc...
        # We could also load the URL and gets its title if it is in HTML.
        basna = lib_util.EncodeUri(fil_script)
        if uprs.netloc != "":
            entity_label = uprs.netloc + "/" + basna
        else:
            entity_label = basna

        # TODO: " " are replaced by "%20". Why ? So change back.
        entity_label = entity_label.replace("%20", " ")

    assert isinstance(entity_graphic_class, str)
    return entity_label, entity_graphic_class, entity_id, entity_host


def ParseEntityUri(uri_with_mode, long_display=True, force_entity_ip_addr=None):
    """Nost of times, the host is not needed."""
    entity_label, entity_graphic_class, entity_id, entity_host = ParseEntityUriWithHost(
        uri_with_mode, long_display=long_display, force_entity_ip_addr=force_entity_ip_addr)
    return entity_label, entity_graphic_class, entity_id


def ParseEntityUriShort(uri):
    return ParseEntityUri(uri, long_display=False, force_entity_ip_addr=None)
