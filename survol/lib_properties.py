import lib_kbase

primns = "http://primhillcomputers.com/ontologies"

#import rdflib
#pc = rdflib.Namespace(primns)
pc = lib_kbase.MakeNamespace(primns)

primns_slash = primns + '/'

# If prp contains a space, it is not properly parsed.
# TODO: The extra parameter is not used yet.
# On voudrait passer plus d informations avec la propriete.
# Actuellement:
# pc.property_smbmount             = MakeProp("smbmount")
# grph.add( ( wbemInstanceNode, pc.property_smbmount, wbemAssocNode ) )
# grph.add( ( wbemInstanceNode, lib_common.MakeProp("AnyString"), wbemAssocNode ) )
#
# if key == pc.property_information
# On voudrait idealement:
# dflib.term.URIRef(primns_slash + "smbmount", key1=val, key2=val2)
# Et aussi, on n'a pas besoin des URIRef.
#   lib_common.NodeLiteral({"type":"html","title":"yawn","color":"blue"})
#   rdflib.term.Literal(u"{'color': 'blue', 'type': 'html', 'title': 'yawn'}")
# Alors on pourrait tout garder pareil sauf les tests d'egalite "html" et "rdf":
# On teste que la clef est en fait un tableau contenant des proprietes.
# On pourrait ajouter des infos dans un certain ordre: "information?key=1", "information?key=2",
# et l ordre naturel conviendra. Ou bien ajouter une fonction de tri dans le sorted.
def MakeProp(prp,**kvargs):
	ret = primns_slash + prp
	if kvargs:
		ret += "?" + "&".join( "%s=%s" for kw in kvargs )
	# TODO: If the key contains a space or "\x20", the result gets prefixed by primns:
	# http://primhillcomputers.com/ontologies/swapnote\ futures
	# If the space is replaced by "%20", everything before it is erased.
	url = ret.replace(" ","_")
	return lib_kbase.MakeNodeUrl( url )

# TODO: Peut-etre: "pc" devrait etre un objet ou on redefinit l appel d un membre,
# ce qui permet de creer dynamiquement des proprietes.

# Property names with this prefix come first in RDF sorting.
# This is a convenient way to have "Information" at the top of properties.
sortPrefix = "----"

# All the properties for creating RDF triples.
# Names must all be different because they are used as keys.
pc.property_pid                  = MakeProp("pid")
pc.property_ppid                 = MakeProp("ppid") # This is rather the parent process.
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
# TODO: APPARENTLY NOT USED ...
pc.property_symbol_oradb         = MakeProp("oradb")
pc.property_oracle_db            = MakeProp("oracle_db")
pc.property_oracle_schema        = MakeProp("schema")
pc.property_oracle_session       = MakeProp("session")
pc.property_oracle_table         = MakeProp("table")
pc.property_oracle_view          = MakeProp("view")
pc.property_oracle_package       = MakeProp("package")
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
pc.property_user                 = MakeProp("user")
pc.property_userid               = MakeProp("userid")
pc.property_owner                = MakeProp("owner")
pc.property_group                = MakeProp("group")
pc.property_groupid              = MakeProp("groupid")
pc.property_file_size            = MakeProp("file_size")
pc.property_file_device          = MakeProp("file_device")
pc.property_script               = MakeProp("script") # Used only in entity.py and the likes, to attach scripts to a node.
pc.property_rdf_data_nolist1     = MakeProp("rdf2")    # These three have a special role.
pc.property_rdf_data_nolist2     = MakeProp("sub-rdf") # Names must all be different
pc.property_rdf_data_nolist3     = MakeProp("sub-rdf2") # Names must all be different
pc.property_wbem_data            = MakeProp("wbem")
pc.property_wmi_data             = MakeProp("wmi")
pc.property_csv_data             = MakeProp("csv")
pc.property_information          = MakeProp(sortPrefix + "Information")
pc.property_domain               = MakeProp("domain")
pc.property_controller           = MakeProp("controller")
pc.property_service              = MakeProp("service")
pc.property_odbc_driver          = MakeProp("odbc_driver")
pc.property_odbc_dsn             = MakeProp("odbc_dsn")
pc.property_odbc_table           = MakeProp("odbc_table")
pc.property_odbc_column          = MakeProp("column")
pc.property_odbc_procedure       = MakeProp("odbc_procedure")
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
pc.property_equivalent           = MakeProp("equivalent")

# Couleur des aretes.
# TODO: L utiliser pour les colonnes des tables.
# TODO: Faire varier la couleur en ayant des arguments CGI.
def prop_color(prop):
	if prop == pc.property_script:
		return "RED"
	if prop == pc.property_rdf_data_nolist1:
		return "BLUE"
	if prop == pc.property_socket_end:
		return "ORANGE"
	return "PURPLE"

