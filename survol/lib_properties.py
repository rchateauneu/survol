import rdflib

# This is an RDF prefix.
primns = "http://www.primhillcomputers.com/survol"

pc = rdflib.Namespace(primns)

prefix_terminator = "#"
primns_slash = primns + prefix_terminator


# If prp contains a space, it is not properly parsed.
# TODO: The extra parameter is not used yet.
# The parameters are intended to pass more information with it.
# At the moment:
# pc.property_smbmount             = MakeProp("smbmount")
# grph.add( ( wbemInstanceNode, pc.property_smbmount, wbemAssocNode ) )
# grph.add( ( wbemInstanceNode, lib_common.MakeProp("AnyString"), wbemAssocNode ) )
#
# if key == pc.property_information
# Ideally we would like:
# dflib.term.URIRef(primns_slash + "smbmount", key1=val, key2=val2)
# Also, no need of URIRef.
#   rdflib.Literal({"type":"html","title":"yawn","color":"blue"})
#   rdflib.term.Literal(u"{'color': 'blue', 'type': 'html', 'title': 'yawn'}")
# So we could keep everything identical excel equality tests 2html" and "rdf":
# It tests that the key is in fact an array containing the properties.
# We could add information in a given order: "information?key=1", "information?key=2",
# Natural order should be OK. or add a sort function in the call to sorted().
def MakeProp(*prps, **kvargs):
    # The delimiter must be compatible with XML because for example, the tag:
    # "<ldt:odbc:column rdf:resource=..."
    # is rejected with the error: "SAXParseException: <unknown>:93:13: not well-formed (invalid token)"
    # The convention is that triple-underscore can only be a separator.
    # It is a very rare situation at the moment, and might change.
    ret = primns_slash + "___".join(prps)
    if kvargs:
        ret += "?" + "&amp;".join( "%s=%s" % (k, kvargs[k]) for k in kvargs)

    # TODO: If the key contains a space or "\x20", the result gets prefixed by primns:
    # http://primhillcomputers.com/ontologies/swapnote\ futures
    # If the space is replaced by "%20", everything before it is erased.
    url = ret.replace(" ","_").replace("-","_")
    return rdflib.term.URIRef( url )


#MakeNodeForSparql = MakeProp


# See lib_kbase.qname
# ... and lib_sparql_custom_evals.survol_url = "http://www.primhillcomputers.com/survol#"
def PropToQName(property_node):
    # property_node is a <class 'rdflib.term.URIRef'>, ex "rdflib.term.URIRef(u'http://primhillcomputers.com/survol/QuotaPagedPoolUsage')"
    # TODO: Should call compute_qname ?
    str_prop = str(property_node).rpartition("/")[2]
    # If "survol#Handle" for example.
    if str_prop.startswith("survol#"):
        str_prop = str_prop[7:]
    return str_prop


def MakeNodeForSparql(property_node):
    # property_node is a <class 'rdflib.term.URIRef'>, ex "rdflib.term.URIRef(u'http://primhillcomputers.com/survol/QuotaPagedPoolUsage')"
    # TODO: Should call compute_qname ?
    str_prop = str(property_node).rpartition("/")[2]
    return str_prop

# TODO: Maybe "pc" could be an object, or redefine a call to a member,
# which would allow to dynamically create properties.

# Property names with this prefix come first in RDF sorting.
# This is a convenient way to have "Information" at the top of properties.
# Use underscores, because hyphen are transformed.
sortPrefix = "____"

# TODO: This should be renamed "predicate" instead of "property".

# TODO: Add description in each property.

# All the properties for creating RDF triples.
# Names must all be different because they are used as keys.
pc.property_pid                  = MakeProp("pid") # TODO: Replace "pid" by "Handle" which is CIM standard.
pc.property_ppid                 = MakeProp("ppid") # TODO: Rename "parent" or "parent_process". See "ParentProcessId".
pc.property_command              = MakeProp("command")
pc.property_host                 = MakeProp("host")
pc.property_hostname             = MakeProp("hostname")
pc.property_netbios              = MakeProp("netbios")
pc.property_domain               = MakeProp("domain")
pc.property_smbview              = MakeProp("smbview")
pc.property_smbshare             = MakeProp("smbshare")
pc.property_smbmount             = MakeProp("smbmount")
pc.property_interface            = MakeProp("interface")
# This property is used with objects of different types: Process, mysqlIds and hosts.
pc.property_has_socket           = MakeProp("has_socket")
pc.property_socket_end           = MakeProp("socket_end")
pc.property_ip_addr              = MakeProp("ip_addr")
pc.property_open_file            = MakeProp("open_file")
pc.property_mapped               = MakeProp("mapped")
pc.property_memmap               = MakeProp("memmap")
pc.property_mysql_id             = MakeProp("mysql_id")
pc.property_disk_used            = MakeProp("disk_used")
pc.property_disk_free            = MakeProp("disk_free")
pc.property_module_dep           = MakeProp("module_dep")
pc.property_argument             = MakeProp("argument")
pc.property_symbol_defined       = MakeProp("symbol_defined")
pc.property_symbol_declared      = MakeProp("symbol_declared")
pc.property_symbol_type          = MakeProp("symbol_type")
pc.property_member               = MakeProp("member")
pc.property_library_depends      = MakeProp("library_depends")
pc.property_library_cpu          = MakeProp("library_cpu")
pc.property_symlink              = MakeProp("symlink")
pc.property_mount                = MakeProp("mount")
pc.property_partition            = MakeProp("partition")
pc.property_mount_options        = MakeProp("options")
pc.property_file_system          = MakeProp("file_system")
pc.property_cwd                  = MakeProp("cwd")
pc.property_oracle_db            = MakeProp("oracle_db")
pc.property_oracle_schema        = MakeProp("schema")
pc.property_oracle_session       = MakeProp("session")
pc.property_oracle_table         = MakeProp("table")
pc.property_oracle_view          = MakeProp("view")
pc.property_oracle_package       = MakeProp("package")
pc.property_oracle_package_body  = MakeProp("package_body")
pc.property_oracle_trigger       = MakeProp("trigger")
pc.property_oracle_sequence      = MakeProp("sequence")
pc.property_oracle_type          = MakeProp("type")
pc.property_oracle_synonym       = MakeProp("synonym")
pc.property_oracle_library       = MakeProp("library")
pc.property_oracle_function      = MakeProp("function")
pc.property_oracle_procedure     = MakeProp("procedure")
pc.property_oracle_depends       = MakeProp("depends")
pc.property_runs                 = MakeProp("runs")
pc.property_calls                = MakeProp("calls")
pc.property_defines              = MakeProp("defines")
pc.property_directory            = MakeProp("directory")
pc.property_user                 = MakeProp("account")
pc.property_userid               = MakeProp("userid")
pc.property_owner                = MakeProp("owner")
pc.property_group                = MakeProp("group")
pc.property_groupid              = MakeProp("groupid")
pc.property_file_size            = MakeProp("file_size")
pc.property_file_device          = MakeProp("file_device")
pc.property_script               = MakeProp("script", property_description="Data source") # Used only in entity.py and the likes, to attach scripts to a node.
pc.property_rdf_data_nolist1     = MakeProp("Data1") # These three have a special role.
pc.property_rdf_data_nolist2     = MakeProp("Data2") # Names must all be different
pc.property_rdf_data_nolist3     = MakeProp("Data3") # Names must all be different
pc.property_wbem_data            = MakeProp("wbem")
pc.property_wmi_data             = MakeProp("wmi")
pc.property_survol_agent         = MakeProp("survol_agent")
pc.property_csv_data             = MakeProp("csv")
pc.property_information          = MakeProp(sortPrefix + "Information")
pc.property_domain               = MakeProp("domain")
pc.property_controller           = MakeProp("controller")
pc.property_service              = MakeProp("service")
# The "odbc" prefix is a kind of namespace.
pc.property_odbc_driver          = MakeProp("odbc","driver")
pc.property_odbc_dsn             = MakeProp("odbc","dsn")
pc.property_odbc_table           = MakeProp("odbc","table")
pc.property_odbc_column          = MakeProp("odbc","column")
pc.property_odbc_procedure       = MakeProp("odbc","procedure")
pc.property_odbc_catalog         = MakeProp("odbc","catalog")
pc.property_odbc_schema          = MakeProp("odbc","schema")
pc.property_odbc_inputs          = MakeProp("odbc","inputs")
pc.property_odbc_outputs         = MakeProp("odbc","outputs")
pc.property_odbc_result          = MakeProp("odbc","result")
pc.property_odbc_remarks         = MakeProp("odbc","remarks")
pc.property_odbc_type            = MakeProp("odbc","type")
pc.property_sqlserver_db         = MakeProp("sqlserver DB")
pc.property_last_access          = MakeProp("last_access")
pc.property_last_change          = MakeProp("last_update")
pc.property_last_metadata_change = MakeProp("metadata_update")
pc.property_service_state        = MakeProp("service_state")
pc.property_com_version          = MakeProp("com_version")
pc.property_com_entry            = MakeProp("com_entry")
pc.property_com_dll              = MakeProp("com_dll")
pc.property_file_system_type     = MakeProp("file_system")
pc.property_notified_file_change = MakeProp("change")
pc.property_wbem_server          = MakeProp("wbem_server")
pc.property_cim_subnamespace     = MakeProp("cim_namespace")
pc.property_class_instance       = MakeProp("instance")
pc.property_subclass             = MakeProp("subclass")
pc.property_cim_subclass         = MakeProp("cim subclass")
pc.property_alias                = MakeProp("alias")
pc.property_string_occurrence    = MakeProp("string occurrence")
pc.property_error                = MakeProp("Error")
pc.property_argv                 = MakeProp("argv")

pc.meta_property_commutative     = MakeProp("commutative_property")
pc.meta_property_collapsed       = MakeProp("collapsed_property")

dictPropertiesGraphAttributes = {
    pc.property_script: "GREEN",
    pc.property_rdf_data_nolist1: "BLUE",
    pc.property_socket_end: "ORANGE",
    pc.property_alias: "RED"
}

# TODO: It should be used for tables columns colors.
# TODO: Change the color based on arguments.
def prop_color(prop):
    try:
        return dictPropertiesGraphAttributes[prop]
    except KeyError:
        return "PURPLE"


_graphic_metadata_node = rdflib.URIRef("layout_style")


def add_property_metadata_to_graph(grph, predicate_node, meta_property_node):
    """
    This adds to the graph, information about how to display some triples:
    - If properties are commutative suh as sockets
    - If properties are "collapsed", that is, if the triples of a common subject must be displayed
      in tables (like in HTML) or in graph.

    See lib_kbase.CreateRdfsOntology which also injects extra triples into a RDF graph, but for another reason.
    """
    grph.add((_graphic_metadata_node, predicate_node, meta_property_node))


def _get_collapsed_properties(grph):
    return [
        the_predicate
        for the_subject, the_predicate, the_object
        in grph.triples((_graphic_metadata_node, None, pc.meta_property_collapsed))
    ]


def extract_properties_metadata(grph):
    """
    This reads from the graph meta data about properties which are used when display in DOT format.
    It might be used in other display modes.
    """
    collapsed_properties = _get_collapsed_properties(grph)

    # This is hard-coded for the moment. It is the only know commutative property,
    # whose edge is displayed as a double arrow.
    commutative_properties = [pc.property_socket_end,]
    grph.remove((_graphic_metadata_node, None, None))
    return collapsed_properties, commutative_properties
