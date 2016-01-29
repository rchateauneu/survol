import rdflib

primns = "http://primhillcomputers.com/ontologies"
pc = rdflib.Namespace(primns)
primns_slash = primns + '/'

# All the properties for creating RDF triples.
# Names must all be different because they are used as keys.
pc.property_pid                  = rdflib.term.URIRef(primns_slash + "pid")
pc.property_ppid                 = rdflib.term.URIRef(primns_slash + "ppid") # This is rather the parent process.
pc.property_command              = rdflib.term.URIRef(primns_slash + "command")
pc.property_host                 = rdflib.term.URIRef(primns_slash + "host")
pc.property_hostname             = rdflib.term.URIRef(primns_slash + "hostname")
pc.property_netbios              = rdflib.term.URIRef(primns_slash + "netbios")
pc.property_domain               = rdflib.term.URIRef(primns_slash + "domain")
pc.property_smbview              = rdflib.term.URIRef(primns_slash + "smbview")
pc.property_smbshare             = rdflib.term.URIRef(primns_slash + "smbshare")
pc.property_smbmount             = rdflib.term.URIRef(primns_slash + "smbmount")
pc.property_interface            = rdflib.term.URIRef(primns_slash + "interface")
# This property is used with objects of different types: Process, mysqlIds and hosts.
pc.property_has_socket           = rdflib.term.URIRef(primns_slash + "has_socket")
pc.property_socket_end           = rdflib.term.URIRef(primns_slash + "socket_end")
pc.property_ip_addr              = rdflib.term.URIRef(primns_slash + "ip_addr")
pc.property_open_file            = rdflib.term.URIRef(primns_slash + "open_file")
pc.property_mapped               = rdflib.term.URIRef(primns_slash + "mapped")
pc.property_memmap               = rdflib.term.URIRef(primns_slash + "memmap")
pc.property_mysql_id             = rdflib.term.URIRef(primns_slash + "mysql_id")
pc.property_disk_used            = rdflib.term.URIRef(primns_slash + "disk_used")
pc.property_disk_free            = rdflib.term.URIRef(primns_slash + "disk_free")
pc.property_module_dep           = rdflib.term.URIRef(primns_slash + "module_dep")
pc.property_symbol_defined       = rdflib.term.URIRef(primns_slash + "symbol_defined")
pc.property_symbol_declared      = rdflib.term.URIRef(primns_slash + "symbol_declared")
pc.property_symbol_type          = rdflib.term.URIRef(primns_slash + "symbol_type")
pc.property_member               = rdflib.term.URIRef(primns_slash + "member")
pc.property_library_depends      = rdflib.term.URIRef(primns_slash + "library_depends")
pc.property_library_cpu          = rdflib.term.URIRef(primns_slash + "library_cpu")
pc.property_symlink              = rdflib.term.URIRef(primns_slash + "symlink")
pc.property_mount                = rdflib.term.URIRef(primns_slash + "mount")
pc.property_partition            = rdflib.term.URIRef(primns_slash + "partition")
pc.property_mount_options        = rdflib.term.URIRef(primns_slash + "options")
pc.property_file_system          = rdflib.term.URIRef(primns_slash + "file_system")
pc.property_cwd                  = rdflib.term.URIRef(primns_slash + "cwd")
# TODO: APPARENTLY NOT USED ...
pc.property_symbol_oradb         = rdflib.term.URIRef(primns_slash + "oradb")
pc.property_oracle_db            = rdflib.term.URIRef(primns_slash + "oracle_db")
pc.property_oracle_schema        = rdflib.term.URIRef(primns_slash + "schema")
pc.property_oracle_session       = rdflib.term.URIRef(primns_slash + "session")
pc.property_oracle_table         = rdflib.term.URIRef(primns_slash + "table")
pc.property_oracle_view          = rdflib.term.URIRef(primns_slash + "view")
pc.property_oracle_package       = rdflib.term.URIRef(primns_slash + "package")
pc.property_oracle_depends       = rdflib.term.URIRef(primns_slash + "depends")
pc.property_runs                 = rdflib.term.URIRef(primns_slash + "runs")
pc.property_calls                = rdflib.term.URIRef(primns_slash + "calls")
pc.property_defines              = rdflib.term.URIRef(primns_slash + "defines")
pc.property_directory            = rdflib.term.URIRef(primns_slash + "directory")
pc.property_user                 = rdflib.term.URIRef(primns_slash + "user")
pc.property_userid               = rdflib.term.URIRef(primns_slash + "userid")
pc.property_owner                = rdflib.term.URIRef(primns_slash + "owner")
pc.property_group                = rdflib.term.URIRef(primns_slash + "group")
pc.property_groupid              = rdflib.term.URIRef(primns_slash + "groupid")
pc.property_file_size            = rdflib.term.URIRef(primns_slash + "file_size")
pc.property_file_device          = rdflib.term.URIRef(primns_slash + "file_device")
pc.property_rdf_data             = rdflib.term.URIRef(primns_slash + "rdf")
pc.property_rdf_data_nolist      = rdflib.term.URIRef(primns_slash + "sub-rdf") # Names must all be different
pc.property_html_data            = rdflib.term.URIRef(primns_slash + "html")
pc.property_wbem_data            = rdflib.term.URIRef(primns_slash + "wbem")
pc.property_wmi_data             = rdflib.term.URIRef(primns_slash + "wmi")
pc.property_csv_data             = rdflib.term.URIRef(primns_slash + "csv")
pc.property_information          = rdflib.term.URIRef(primns_slash + "information")
pc.property_image                = rdflib.term.URIRef(primns_slash + "image")
pc.property_domain               = rdflib.term.URIRef(primns_slash + "domain")
pc.property_controller           = rdflib.term.URIRef(primns_slash + "controller")
pc.property_service              = rdflib.term.URIRef(primns_slash + "service")
pc.property_odbc_driver          = rdflib.term.URIRef(primns_slash + "odbc_driver")
pc.property_odbc_dsn             = rdflib.term.URIRef(primns_slash + "odbc_dsn")
pc.property_last_access          = rdflib.term.URIRef(primns_slash + "last_access")
pc.property_last_change          = rdflib.term.URIRef(primns_slash + "last_change")
pc.property_last_metadata_change = rdflib.term.URIRef(primns_slash + "last_metadata_change")
pc.property_service_state        = rdflib.term.URIRef(primns_slash + "service_state")
pc.property_com_version          = rdflib.term.URIRef(primns_slash + "com_version")
pc.property_com_entry            = rdflib.term.URIRef(primns_slash + "com_entry")
pc.property_com_dll              = rdflib.term.URIRef(primns_slash + "com_dll")
pc.property_file_system_type     = rdflib.term.URIRef(primns_slash + "file_system")
pc.property_notified_file_change = rdflib.term.URIRef(primns_slash + "change")
pc.property_wbem_server          = rdflib.term.URIRef(primns_slash + "wbem_server")
pc.property_cim_subnamespace     = rdflib.term.URIRef(primns_slash + "cim_namespace")
pc.property_class_instance       = rdflib.term.URIRef(primns_slash + "instance")
pc.property_subclass             = rdflib.term.URIRef(primns_slash + "subclass")

def color(prop):
	if prop == pc.property_rdf_data:
		return "RED"
	if prop == pc.property_html_data:
		return "BLUE"
	if prop == pc.property_socket_end:
		return "ORANGE"
	return "BLACK"

