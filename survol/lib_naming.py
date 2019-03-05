import lib_util
import lib_mime
import cgi
import sys
import os
import re
import lib_patterns

################################################################################

# TODO: Make this dynamic, less hard-coded.
def UriToTitle(uprs):
    # Maybe an external URI sending data in RDF, HTML etc...
    # We could also load the URL and gets its title if it is in HTML.
    # urlparse('http://www.cwi.nl:80/%7Eguido/Python.html')
    # ParseResult(scheme='http', netloc='www.cwi.nl:80', path='/%7Eguido/Python.html', params='', query='', fragment='')
    basna = lib_util.EncodeUri( os.path.basename( uprs.path ) )
    if uprs.netloc != "":
        return uprs.netloc + "/" + basna
    else:
        return basna

################################################################################

def EntityArrToLabel(entity_type,entity_ids_arr):
    funcEntityName = lib_util.HierarchicalFunctionSearch(entity_type,"EntityName")

    if funcEntityName:
        entity_name = funcEntityName(entity_ids_arr)
        return entity_name

    # General case of a URI created by us and for us.
    ent_ids_joined = ",".join(entity_ids_arr)
    if lib_patterns.TypeToGraphParams( entity_type ) is None:
        # If the type does not have a special color, add its name.
        return  "%s (%s)" % ( ent_ids_joined, entity_type )
    else:
        return ent_ids_joined

# This calls for an object, the class-specific function UniversalAlias, if it exists.
# Otherwise, it generates a default string with the object's parameters.
# The universal alias of an object is the same for all Survol agents no matter what
# the host they are running on, or their URL.
# Therefore, if several agents are running on the same machine but are hosted differently
# (Apache, IIS, cgiserver.py script running with different accounts and different port numbers),
# they will calculate the same universal alias for the same objects, even if
# the URLs are different.
def EntityArrToAlias(entity_type,entity_ids_arr,force_entity_ip_addr ):

    funcUniversalAlias = lib_util.HierarchicalFunctionSearch(entity_type,"UniversalAlias")

    if funcUniversalAlias:
        univAlias = funcUniversalAlias(entity_ids_arr,force_entity_ip_addr,entity_type)
    else:
        # The default alias must contain the class name otherwise there could be an ambiguity
        # between objects of different classes, on the same machine with the attributes values.
        ent_ids_joined = ",".join(entity_ids_arr)

        # This adds a hostname to the moniker, with the Survol syntax.
        # But maybe this object will be described by WBEM or WMI.
        univAlias = "%s@%s:%s" % (force_entity_ip_addr, entity_type, ent_ids_joined)

    #sys.stderr.write("EntityArrToAlias entity_type=%s entity_ids_arr=%s force_entity_ip_addr=%s univAlias=%s\n"
    #                 %(entity_type,str(entity_ids_arr),force_entity_ip_addr,univAlias) )
    return univAlias

# For an association, we might have:
# entity_id=Dependent=root/cimv2:LMI_StorageExtent.CreationClassName="LMI_StorageExtent",SystemCreationClassName="PG_ComputerSystem" Antecedent=root/cimv2:LMI_DiskDrive.CreationClassName="LMI_DiskDrive",DeviceID="/dev/sda"
# This is not easy to manage but avoids ambiguities.
def EntityToLabel(entity_type,entity_ids_concat,force_entity_ip_addr):
    # sys.stderr.write("EntityToLabel entity_id=%s entity_type=%s\n" % ( entity_ids_concat, entity_type ) )

    # Specific case of objtypes.py
    if not entity_ids_concat:
        return entity_type

    # TODO: Robust logic as long as the value does not contain an '=' sign.
    splitKV = lib_util.SplitMoniker(entity_ids_concat)

    # Now build the array of values in the ontology order.
    ontoKeys = lib_util.OntologyClassKeys(entity_type)

    # Default value if key is missing.
    entity_ids_arr = [ splitKV.get( keyOnto, keyOnto + "?" ) for keyOnto in ontoKeys ]

    if force_entity_ip_addr:
        entity_label = EntityArrToAlias(entity_type,entity_ids_arr,force_entity_ip_addr)
    else:
        entity_label = EntityArrToLabel(entity_type,entity_ids_arr)
    # sys.stderr.write("EntityToLabel entity_label=%s\n" % entity_label )

    # There might be extra properties which are not in our ontology.
    # This happens if duplicates from WBEM or WMI. MAKE THIS FASTER ?
    # Both must be sets, otherwise unsupported operation.

    # TODO: This set could be created once and for all. But the original order must be kept.
    setOntoKeys = set(ontoKeys)

    # This appends the keys which are not part of the normal ontology, therefore bring extra information.
    # This is rather slow and should normally not happen.
    for ( extPrpKey, extPrpVal ) in splitKV.items():
        if not extPrpKey in setOntoKeys:
            entity_label += " %s=%s" % ( extPrpKey, extPrpVal )

    return entity_label

# Called when using the specific CGI script.
def ParseEntitySurvolUri(uprs,longDisplay, force_entity_ip_addr):
    # sys.stderr.write("KnownScriptToTitle filScript=%s uprs=%s\n"%(filScript,str(uprs)))
    # uprs=ParseResult(
    #   scheme=u'http',
    #   netloc=u'127.0.0.1:8000',
    #   path=u'/survol/survolcgi.py',
    #   params='',
    #   query=u'script=/entity.py&amp;amp;xid=Win32_UserAccount.Domain=rchateau-HP,Name=rchateau',
    #   fragment='')
    # Maybe the script is run in the CGI script.
    # If so, we have to rebuild a valid URL.
    uprsQuery = uprs.query
    # Apparently the URL might contain "&amp;amp;" and "&" playing the same role.
    # It does not matter as it is purely cosmetic.
    # uprsQuery = uprsQuery.replace("&amp;amp;","&")
    uprsQuery = lib_util.UrlNoAmp(uprsQuery)
    spltCgiArgs = uprsQuery.split("&")
    #spltCgiArgs = uprsQuery.split("&amp;amp;")
    queryRebuild = ""
    queryDelim = "?"
    scriptRebuilt = None
    for oneSplt in spltCgiArgs:
        spltKV = oneSplt.split("=")
        # sys.stderr.write("spltKV=%s\n"%spltKV)
        if spltKV[0] == "script":
            scriptRebuilt = "=".join(spltKV[1:])
        else:
            queryRebuild += queryDelim + oneSplt
            queryDelim = "&"

    if scriptRebuilt:
        urlRebuilt = uprs.scheme + "://" + uprs.netloc + scriptRebuilt + queryRebuild
        # sys.stderr.write("ParseEntitySurvolUri urlRebuilt=%s\n"%(urlRebuilt))

        # ( labText, subjEntityGraphicClass, entity_id)
        return ParseEntityUri(urlRebuilt, longDisplay, force_entity_ip_addr)
    else:
        return ( "Incomplete CGI script:"+str(uprs), "Unknown subjEntityGraphicClass", "Unknown entity_id" )


# TODO: Hard-coded but OK for the moment.
# Use the "__doc__" string in each file.
scripts_to_titles = {
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
    "entity.py":"",
    "entity_wbem.py":"WBEM",
    "entity_wmi.py":"WMI",
}

def KnownScriptToTitle(filScript,uriMode,entity_host = None,entity_suffix=None):
    # Extra information depending on the script.

    # Special display if MIME URL
    if filScript == "entity_mime.py":
        if not entity_suffix:
            entity_suffix = "None"
        # The Mime type is embedded into the mode, after a "mime:" prefix.
        entity_label = entity_suffix + " ("+ lib_mime.ModeToMimeType(uriMode)+")"
        return entity_label

    # The label is a Survol module name which is a class (With an EntityOntology() function),
    #  or a namespace. So we give the right title.
    if filScript == "class_type_all.py":
        moduOntology = lib_util.OntologyClassKeys(entity_suffix)
        if moduOntology:
            entity_label = entity_suffix + " (Class)"
        else:
            entity_label = entity_suffix + " (Domain)"
        return entity_label

    try:
        entity_label = scripts_to_titles[ filScript ]
    except KeyError:
        entity_label = filScript + "..."

    if entity_suffix:
        if entity_label:
            entity_label = entity_suffix + " ("+ entity_label+")"
        else:
            entity_label = entity_suffix

    # Maybe hostname is a CIMOM address (For WBEM) or a machine name.
    if entity_host:
        if not lib_util.IsLocalAddress( entity_host ):
            # If this is a CIMOM, make it shorter: "http://vps516494.ovh.net:5988" or ""https://vps516494.ovh.net:5989"
            host_only = lib_util.EntHostToIp( entity_host )
            entity_label += " at " + host_only

    # TODO: Add the host name in the title.

    return entity_label


def CalcLabel(entity_host,entity_type,entity_id,force_entity_ip_addr,filScript):
    ( namSpac, entity_type_NoNS, _ ) = lib_util.ParseNamespaceType(entity_type)

    if not force_entity_ip_addr and not lib_util.IsLocalAddress(entity_host):
        entity_label = None
        if filScript == "entity_wbem.py":
            import lib_wbem
            # Because of WBEM, entity_host is a CIMOM url, like "http://vps516494.ovh.net:5988"
            entity_label = lib_wbem.EntityToLabelWbem(namSpac, entity_type_NoNS, entity_id, entity_host)
            if not entity_label:
                # Fallback to Survol label.
                actual_host = lib_util.EntHostToIp(entity_host)

                entity_label = EntityToLabel(entity_type_NoNS, entity_id, actual_host)
        elif filScript == "entity_wmi.py":
            import lib_wmi
            # For WMI, the hostname is a NETBIOS machine name.
            entity_label = lib_wmi.EntityToLabelWmi(namSpac, entity_type_NoNS, entity_id, entity_host)
            if not entity_label:
                # Fallback to Survol label.
                actual_host = lib_util.EntHostToIp(entity_host)
                entity_label = EntityToLabel(entity_type_NoNS, entity_id, actual_host)
        else:
            # filScript in [ "class_type_all.py", "entity.py" ], or if no result from WMI or WBEM.
            entity_label = EntityToLabel(entity_type_NoNS, entity_id, entity_host)

    elif entity_type_NoNS or entity_id:
        entity_label = EntityToLabel( entity_type_NoNS, entity_id, force_entity_ip_addr )
    else:
        # Only possibility to print something meaningful.
        entity_label = namSpac

    # Some corner cases: "http://127.0.0.1/Survol/survol/entity.py?xid=CIM_ComputerSystem.Name="
    if not entity_label:
        entity_label = entity_type

    return entity_label




# Extracts the entity type and id from a URI, coming from a RDF document. This is used
# notably when transforming RDF into dot documents.
# The returned entity type is used for choosing graphic attributes and gives more information than the simple entity type.
# (labText, entity_graphic_class, entity_id) = lib_naming.ParseEntityUri( unquote(obj) )
# "http://192.168.0.17/yawn/GetClass/CIM_UnixProcess?url=http%3A%2F%2F192.168.0.17%3A5988&amp;amp;verify=0&amp;amp;ns=root%2Fcimv2"
def ParseEntityUri(uriWithMode,longDisplay=True, force_entity_ip_addr = None):
    #sys.stderr.write("ParseEntityUri uriWithMode=%s\n"%uriWithMode)

    # Maybe there is a host name before the entity type. It can contain letters, numbers,
    # hyphens, dots etc... but no ":" or "@".
    # THIS CANNOT WORK WITH IPV6 ADDRESSES...
    # WE MAY USE SCP SYNTAX: scp -6 osis@\[2001:db8:0:1\]:/home/osis/test.file ./test.file

    # In the URI, we might have the CGI parameter "&mode=json". It must be removed otherwise
    # it could be taken in entity_id, and the result of EntityToLabel() would be wrong.
    uriWithModeClean = lib_util.UrlNoAmp(uriWithMode)
    uri = lib_util.AnyUriModed(uriWithModeClean, "")
    uriMode = lib_util.GetModeFromUrl(uriWithModeClean)

    uprs = lib_util.survol_urlparse(uri)

    filScript = os.path.basename(uprs.path)
    # sys.stderr.write("ParseEntityUri filScript=%s\n"%filScript)

    # Very specific case when a Survol agent runs on OVH websites, not designed for this usage.
    if filScript == "survolcgi.py":
        return ParseEntitySurvolUri(uprs,longDisplay, force_entity_ip_addr)

    # This works for the scripts:
    # entity.py            xid=namespace/type:idGetNamespaceType
    # objtypes_wbem.py     Just extracts the namespace, as it prefixes the type: xid=namespace/type:id

    # See variable lib_util.xidCgiDelimiter="?xid="
    if uprs.query.startswith("xid="):
        # TODO: Maybe the chain contains HTML codes and therefore cannot be parsed.
        # Ex: "xid=%40%2F%3Aoracle_package." == "xid=@/:oracle_package."
        ( entity_type, entity_id, entity_host ) = lib_util.ParseXid( uprs.query[4:] )

        entity_graphic_class = entity_type

        entity_label = CalcLabel(entity_host,entity_type,entity_id,force_entity_ip_addr,filScript)

        # TODO: Consider ExternalToTitle, similar logic with different results.
        if longDisplay:
            entity_label = KnownScriptToTitle(filScript,uriMode,entity_host,entity_label)

    # Maybe an internal script, but not entity.py
    # It has a special entity type as a display parameter
    elif uri.startswith( lib_util.uriRoot ):
        # This is a bit of a special case which allows to display something if we know only
        # the type of the entity but its id is undefined. Instead of displaying nothing,
        # this attempts to display all available entities of this given type.
        # source_top/enumerate_process.py etc... Not "." because this has a special role in Python.
        mtch_enumerate = re.match( "^.*/enumerate_([a-z0-9A-Z_]*)\.py$", uri )
        if mtch_enumerate :
            entity_graphic_class = mtch_enumerate.group(1)
            entity_id = ""
            # TODO: Change this label, not very nice.
            # This indicates that a specific script can list all objects of a given entity type.
            entity_label = entity_graphic_class + " enumeration"
        else:
            entity_graphic_class = "provider_script"
            entity_id = ""

            entity_label = KnownScriptToTitle(filScript,uriMode)

    elif uri.split(':')[0] in [ "ftp", "http", "https", "urn", "mail" ]:
        # Standard URLs. Example: lib_common.NodeUrl( "http://www.google.com" )
        entity_graphic_class = ""
        entity_id = ""
        # Display the complete URL, otherwise it is not clickable.
        entity_label = uriWithMode # uri # uri.split('/')[2]

    else:
        entity_graphic_class = ""
        entity_id = "PLAINTEXTONLY"
        entity_label = UriToTitle(uprs)
        # TODO: " " are replaced by "%20". Why ? So change back.
        entity_label = entity_label.replace("%20"," ")

    return ( entity_label, entity_graphic_class, entity_id )

def ParseEntityUriShort(uri):
    return ParseEntityUri(uri,longDisplay=False,force_entity_ip_addr = None)
