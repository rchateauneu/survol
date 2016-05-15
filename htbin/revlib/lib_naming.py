import lib_util
import psutil
import cgi
import sys
import os
import re
import lib_patterns
from lib_entities import lib_entity_CIM_Process

try:
	from urlparse import urlparse
except ImportError:
	from urllib.parse import urlparse

################################################################################

# TODO: Make this dynamic, less hard-coded.
def UriToTitle(uprs):
	# Maybe an external URI sending data in RDF, HTML etc...
	# We could also load the URL and gets its title if it is in HTML.
	# urlparse('http://www.cwi.nl:80/%7Eguido/Python.html')
	# ParseResult(scheme='http', netloc='www.cwi.nl:80', path='/%7Eguido/Python.html', params='', query='', fragment='')
	# uprs = urlparse(uri)

	# TODO: Essayer de parser nos autres URLs comme objtypes etc...

	basna = lib_util.EncodeUri( os.path.basename( uprs.path ) )

	if uprs.netloc != "":
		return uprs.netloc + "/" + basna
	else:
		return basna

# TODO: Create a lookup from type to functions.
def EntityArrToLabel(entity_type,entity_ids_arr):

	# Short-cut because one argument is the most common case?
	try:
		entity_id = entity_ids_arr[0]
	except IndexError:
		entity_id = None

	# Nice title depending on the entity type.
	if entity_type == "CIM_Process":
		# If the process is not there, this is not a problem.
		try:
			# sys.stderr.write("psutil.Process entity_id=%s\n" % ( entity_id ) )
			proc_obj = psutil.Process(int(entity_id))
			return lib_entity_CIM_Process.PsutilProcToName(proc_obj)
		except lib_entity_CIM_Process.NoSuchProcess:
			return "No such process:"+entity_id
		except ValueError:
			return "Invalid pid:("+entity_id+")"
		# sys.stderr.write("entity_label=%s\n" % ( entity_label ) )

	if entity_type in [ "symbol", "class" ]:
		# This replace HTML entities. This is necessary because these chars are used
		# in C++ symbols. Anyway, it might be necessary for other entity types.
		return cgi.escape( entity_id )

	if entity_type == "file":
		# A file name can be very long, so it is truncated.
		file_basename = os.path.basename(entity_id)
		if os.path.isdir(entity_id):
			entity_graphic_class = lib_util.ComposeTypes("file","dir")
			if file_basename == "":
				return entity_id
			else:
				# By convention, directory names ends with a "/".
				return file_basename + "/"
		else:
			# If entity_graphic_class contained the file extension, an icon could be displayed.
			if file_basename == "":
				return entity_id
			else:
				return file_basename

	if entity_type in [ "user", "Win32_UserAccount", "addr", "oracle_db", "CIM_ComputerSystem", "smbshr", "com_registered_type_lib", "memmap" ]:
		# The type of some entities can be deduced from their name.
		return entity_id

	if entity_type == "oracle_schema":
		# The type of some entities can be deduced from their name.
		return entity_ids_arr[0] + "." + entity_ids_arr[1]

	if entity_type in [ "oracle_table", "oracle_view", "oracle_package", "oracle_package_body" ]:
		# The type of some entities can be deduced from their name.
		return entity_ids_arr[0] + "." + entity_ids_arr[1] + "." + entity_ids_arr[2]

	# General case of a URI created by us and for us.
	ent_ids_joined = ",".join(entity_ids_arr)
	if lib_patterns.TypeToPattern( entity_type ) is None:
		# If the type does not have a special color, add its name.
		return ent_ids_joined + " (" + entity_type + ")"
	else:
		return ent_ids_joined

# Dans les cas des associations on a pu avoir:
# entity_id=Dependent=root/cimv2:LMI_StorageExtent.CreationClassName="LMI_StorageExtent",SystemCreationClassName="PG_ComputerSystem" Antecedent=root/cimv2:LMI_DiskDrive.CreationClassName="LMI_DiskDrive",DeviceID="/dev/sda"
# Ca n est pas facile a gerer, on va essayer d'eviter ca en amont, en traitant a part les references et les associations.
# Ca se compred car elles sont de toutes facons destinees a etre traitees autrement.
# Notons que SplitMoniker() ne garde que le premier groupe.
def EntityToLabel(entity_type,entity_ids_concat):
	# sys.stderr.write("EntityToLabel entity_id=%s entity_type=%s\n" % ( entity_ids_concat, entity_type ) )

	# Specific case of objtypes.py
	if entity_ids_concat is None or len(entity_ids_concat) == 0:
		return entity_type

	# TODO: Meme logique foireuse mais robuste, tant que la valeur ne contient pas "=".
	# TODO: Des que les choses sont stables, on mettra "=" dans tous les URLs.
	# TODO: Mais il faut un dictionnaire de donnees pour toutes les classes.
	# VERY SLOW !!!
	splitKV = lib_util.SplitMoniker(entity_ids_concat)

	# Now build the array of values in the ontology order.
	ontoKeys = lib_util.OntologyClassKeys(entity_type)

	# TODO: On obtient ceci avec des classes externes:
	# 'Id? (MSFT_CliAlias);FriendlyName="Alias" '
	# DONC: OntologyClassKeys() ne devrait renvoyer [ "Id" ] que pour nos classes, par defaut.
	# et sinon une chaine vide.

	# Default value if key is missing.
	entity_ids_arr = [ splitKV.get( keyOnto, keyOnto + "?" ) for keyOnto in ontoKeys ]

	# sys.stderr.write("EntityToLabel entity_ids_arr=%s\n" % str( entity_ids_arr ) )

	entity_label = EntityArrToLabel(entity_type,entity_ids_arr)
	# sys.stderr.write("EntityToLabel entity_label=%s\n" % entity_label )

	# There might be extra properties which are not in our ontology.
	# This happens if duplicates from WBEM or WMI. MAKE THIS FASTER ?
	# Both must be sets, otherwise unsupported operation.

	# TODO: This set could be created once and for all. But the original order must be kept.
	setOntoKeys = set(ontoKeys)

	# This appends the keys which are not part of the normal ontology, therefore bring extra information.
	for ( extPrpKey, extPrpVal ) in splitKV.items():
		if not extPrpKey in setOntoKeys:
			entity_label += " %s=%s" % ( extPrpKey, extPrpVal )

	return entity_label


# TODO: Hard-coded but OK for the moment.
scripts_to_titles = {
	"portal_wbem.py": "WBEM server ",
	"portal_wmi.py": "WMI server ",
	"class_wbem.py": "WBEM class ",
	"class_wmi.py": "WMI class ",
	"class_type_all.py": "Class ",
	"objtypes_wbem.py": "WBEM classes ",
	"objtypes_wmi.py": "WMI classes ",
	"namespaces_wbem.py": "WBEM namespaces ",
	"namespaces_wmi.py": "WMI namespaces ",
	"entity.py":"",
	"entity_wbem.py":"WBEM object",
	"entity_wmi.py":"WMI object"
}

# Extracts the entity type and id from a URI, coming from a RDF document. This is used
# notably when transforming RDF into dot documents.
# The returned entity type is used for choosing graphic attributes and gives
# more information than the simple entity type.
# uri="http://127.0.0.1:80/Survol/htbin/entity.py?xid=CIM_ComputerSystem.Name=Unknown-30-b5-c2-02-0c-b5-2"
def ParseEntityUri(uri):
	# sys.stderr.write("ParseEntityUri %s\n"%uri)
	# Maybe there is a host name before the entity type. It can contain letters, numbers,
	# hyphens, dots etc... but no ":" or "@".
	# THIS CANNOT WORK WITH IPV6 ADDRESSES...
	# WE MAY USE SCP SYNTAX: scp -6 osis@\[2001:db8:0:1\]:/home/osis/test.file ./test.file

	# from urlparse import urlparse
	# urlparse("http://127.0.0.1:80/Survol/htbin/entity.py?xid=CIM_ComputerSystem.Name=Unknown-30-b5-c2-02-0c-b5-2")
	# ParseResult(scheme='http', netloc='127.0.0.1:80', path='/Survol/htbin/entity.py', params='', query='xid=CIM_ComputerSystem.Name=Unknown-30-b5-c2-02-0c-b5-2', fragment='')

	uprs = urlparse(uri)

	# This works for the scripts:
	# entity.py            xid=namespace/type:idGetNamespaceType
	# objtypes_wbem.py     Just extracts the namespace, as it prefixes the type: xid=namespace/type:id
	entity_host = ""

	if uprs.query.startswith("xid="):
		# TODO: La chaine contient peut-etre des codages HTML et donc ne peut pas ete parsee !!!!!!
		# Ex: "xid=%40%2F%3Aoracle_package." == "xid=@/:oracle_package."
		( entity_type, entity_id, entity_host ) = lib_util.ParseXid( uprs.query[4:] )

		entity_graphic_class = entity_type

		( namSpac, entity_type_NoNS, _ ) = lib_util.ParseNamespaceType(entity_type)

		if entity_type_NoNS == "" and entity_id == "":
			# Only possibility to print something meaningful.
			entity_label = namSpac
		else:
			entity_label = EntityToLabel( entity_type_NoNS, entity_id )

		# Some corner cases: "http://127.0.0.1/Survol/htbin/entity.py?xid=CIM_ComputerSystem.Name="
		if entity_label == "":
			entity_label = entity_type

		# Extra information depending on the script.
		filScript = os.path.basename(uprs.path)
		try:
			extra_title = scripts_to_titles[ filScript ]
			entity_label = extra_title + " " + entity_label
		except KeyError:
			entity_label = filScript +" "+ entity_label

	# Maybe an internal script, but not entity.py
	# It has a special entity type as a display parameter
	elif uri.startswith( lib_util.uriRoot ):
		# This is a bit of a special case which allows to display something if we know only
		# the type of the entity but its id is undefined. Instead of displaying nothing,
		# this attempts to display all available entities of this given type.
		# source_top/enumerate.process.py etc...
		mtch_enumerate = re.match( "^.*/enumerate\.([a-z0-9A-Z_]*)\.py$", uri )
		if mtch_enumerate :
			entity_graphic_class = mtch_enumerate.group(1)
			entity_id = ""
			# TODO: Change this label, not very nice.
			# This indicates that a specific script can list all objects of a given entity type.
			entity_label = entity_graphic_class + " enumeration"
		else:
			entity_graphic_class = lib_util.ComposeTypes("file","script")
			entity_id = ""
			entity_label = UriToTitle(uprs)

	elif uri.split(':')[0] in [ "ftp", "http", "urn" ]:
		# These are standard URLs. More could be added.
		entity_graphic_class = ""
		entity_id = ""
		entity_label = uri.split('/')[2]

	else:
		entity_graphic_class = ""
		entity_id = ""
		entity_label = UriToTitle(uprs)

	# Maybe hostname is a CIMOM address.
	if not lib_util.IsLocalAddress( entity_host ):
		entity_label += " at " + entity_host

	entity_label = entity_label.replace("&","&amp;")
	return ( entity_label, entity_graphic_class, entity_id )

