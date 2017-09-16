import lib_util
import cgi
import sys
import os
import re
import lib_patterns

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

################################################################################

DictEntityNameFunctions = {}

def EntityArrToLabel(entity_type,entity_ids_arr,entity_host):
	global DictEntityNameFunctions

	try:
		funcEntNam = DictEntityNameFunctions[entity_type]
		return funcEntNam(entity_ids_arr,entity_host)
	except KeyError:
		pass

	# Si on ne trouve pas le module on utilise la fonction par defaut.
	# { "file" : sources_types.file.ArrToLabel, ... }
	entity_module = lib_util.GetEntityModule(entity_type)
	if 	entity_module:
		try:
			# sys.stderr.write("Before calling EntityName: entity_ids_arr=%s\n"%(entity_ids_arr))
			DictEntityNameFunctions[entity_type] = entity_module.EntityName
			entity_name = entity_module.EntityName(entity_ids_arr,entity_host)
			return entity_name
		except AttributeError:
			pass

	# General case of a URI created by us and for us.
	ent_ids_joined = ",".join(entity_ids_arr)
	if lib_patterns.TypeToGraphParams( entity_type ) is None:
		# If the type does not have a special color, add its name.
		return ent_ids_joined + " (" + entity_type + ")"
	else:
		return ent_ids_joined



# Dans les cas des associations on a pu avoir:
# entity_id=Dependent=root/cimv2:LMI_StorageExtent.CreationClassName="LMI_StorageExtent",SystemCreationClassName="PG_ComputerSystem" Antecedent=root/cimv2:LMI_DiskDrive.CreationClassName="LMI_DiskDrive",DeviceID="/dev/sda"
# Ca n est pas facile a gerer, on va essayer d'eviter ca en amont, en traitant a part les references et les associations.
# Ca se compred car elles sont de toutes facons destinees a etre traitees autrement.
# Notons que SplitMoniker() ne garde que le premier groupe.
def EntityToLabel(entity_type,entity_ids_concat, entity_host):
	# sys.stderr.write("EntityToLabel entity_id=%s entity_type=%s\n" % ( entity_ids_concat, entity_type ) )

	# Specific case of objtypes.py
	if not entity_ids_concat:
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

	entity_label = EntityArrToLabel(entity_type,entity_ids_arr,entity_host)
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
# Use the "__doc__" string in each file.
scripts_to_titles = {
	"portal_wbem.py": "WBEM server ",
	"portal_wmi.py": "WMI server ",
	"class_wbem.py": "WBEM class",
	"class_wmi.py": "WMI class",
	"class_type_all.py": "Generic class",
	"file_directory.py": "Directory content",
	"objtypes.py": "Classes hierarchy",
	"objtypes_wbem.py": "WBEM subclasses of ",
	"objtypes_wmi.py": "WMI subclasses of ",
	"namespaces_wbem.py": "WBEM namespaces ",
	"namespaces_wmi.py": "WMI namespaces ",
	"entity.py":"",
	"entity_wbem.py":"WBEM",
	"entity_wmi.py":"WMI",
	"file_to_mime.py":"Mime display"
}

def KnownScriptToTitle(uprs,entity_host = None,entity_suffix=None):
	# Extra information depending on the script.
	filScript = os.path.basename(uprs.path)
	try:
		extra_title = scripts_to_titles[ filScript ]
		entity_label = extra_title
	except KeyError:
		entity_label = filScript

	if entity_suffix:
		entity_label += " "+ entity_suffix

	# Maybe hostname is a CIMOM address.
	if entity_host:
		if not lib_util.IsLocalAddress( entity_host ):
			entity_label += " at " + entity_host

	return entity_label

# Extracts the entity type and id from a URI, coming from a RDF document. This is used
# notably when transforming RDF into dot documents.
# The returned entity type is used for choosing graphic attributes and gives more information than the simple entity type.
# (labText, entity_graphic_class, entity_id) = lib_naming.ParseEntityUri( unquote(obj) )
def ParseEntityUri(uriWithMode,longDisplay=True):
	# sys.stderr.write("ParseEntityUri %s\n"%uri)
	# Maybe there is a host name before the entity type. It can contain letters, numbers,
	# hyphens, dots etc... but no ":" or "@".
	# THIS CANNOT WORK WITH IPV6 ADDRESSES...
	# WE MAY USE SCP SYNTAX: scp -6 osis@\[2001:db8:0:1\]:/home/osis/test.file ./test.file

	# from urlparse import urlparse
	# urlparse("http://127.0.0.1:80/Survol/survol/entity.py?xid=CIM_ComputerSystem.Name=Unknown-30-b5-c2-02-0c-b5-2")
	# ParseResult(scheme='http', netloc='127.0.0.1:80', path='/Survol/survol/entity.py', params='', query='xid=CIM_ComputerSystem.Name=Unknown-30-b5-c2-02-0c-b5-2', fragment='')


	# In the URI, we might have the CGI parameter "&mode=json". It must be removed otherwise
	# it could be taken in entity_id, and the result of EntityToLabel() would be wrong.
	uri = lib_util.AnyUriModed(uriWithMode, "")

	uprs = urlparse(uri)

	# This works for the scripts:
	# entity.py            xid=namespace/type:idGetNamespaceType
	# objtypes_wbem.py     Just extracts the namespace, as it prefixes the type: xid=namespace/type:id

	if uprs.query.startswith("xid="):
		# TODO: La chaine contient peut-etre des codages HTML et donc ne peut pas ete parsee !!!!!!
		# Ex: "xid=%40%2F%3Aoracle_package." == "xid=@/:oracle_package."
		( entity_type, entity_id, entity_host ) = lib_util.ParseXid( uprs.query[4:] )

		entity_graphic_class = entity_type

		( namSpac, entity_type_NoNS, _ ) = lib_util.ParseNamespaceType(entity_type)

		if entity_type_NoNS or entity_id:
			entity_label = EntityToLabel( entity_type_NoNS, entity_id, entity_host )
		else:
			# Only possibility to print something meaningful.
			entity_label = namSpac

		# Some corner cases: "http://127.0.0.1/Survol/survol/entity.py?xid=CIM_ComputerSystem.Name="
		if not entity_label:
			entity_label = entity_type

		# TODO: Consider ExternalToTitle, similar logic with different results.
		if longDisplay:
			entity_label = KnownScriptToTitle(uprs,entity_host,entity_label)

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
			entity_graphic_class = lib_util.ComposeTypes("CIM_DataFile","script") # TODO: DOUTEUX...
			entity_id = ""

			entity_label = KnownScriptToTitle(uprs)
			# entity_label = UriToTitle(uprs)

	elif uri.split(':')[0] in [ "ftp", "http", "https", "urn", "mail" ]:
		# Standard URLs. Example: lib_common.NodeUrl( "http://www.google.com" )
		entity_graphic_class = ""
		entity_id = ""
		# Display the complete URL, otherwise it is not clickable.
		entity_label = uri # uri.split('/')[2]

	else:
		entity_graphic_class = ""
		entity_id = "PLAINTEXTONLY"
		entity_label = UriToTitle(uprs)
		# TODO: " " are replaced by "%20". Why ? So change back.
		entity_label = entity_label.replace("%20"," ")

	# TODO: ATTENTION !!!! ON L A RETIRE ICI UNIQUEMENT CAR C ETAIT DEJA FAIT
	# TODO: AVEC LES SYMBOLES. PEUT ETRE LE REMETTRE POUR TOUS LES AUTRES TYPES.
	# entity_label = entity_label.replace("&","&amp;")
	# entity_label = entity_label.escape()
	return ( entity_label, entity_graphic_class, entity_id )

def ParseEntityUriShort(uri):
	return ParseEntityUri(uri,False)
