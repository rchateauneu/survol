#!/usr/bin/python

"""
It receives as CGI arguments, the entity type and its id. Some examples: process/pid, file/path, etc...
"""

import os
import re
import sys
import psutil
import rdflib
import lib_infocache
import importlib

import lib_util
import lib_common
import lib_wbem
import lib_wmi
from lib_properties import pc

import lib_entities.lib_entity_CIM_Process as lib_entity_CIM_Process
import lib_entities.lib_entity_CIM_ComputerSystem as lib_entity_CIM_ComputerSystem

# This can process remote hosts because it does not call any script, just shows them.
cgiEnv = lib_common.CgiEnv("RDF data sources", can_process_remote = True)
entity_id = cgiEnv.m_entity_id
entity_host = cgiEnv.GetHost()

( nameSpace, entity_type, entity_namespace_type ) = cgiEnv.GetNamespaceType()

is_host_remote = not entity_host in [ None, "", "localhost", "127.0.0.1", lib_common.hostName ]

sys.stderr.write("entity: entity_host=%s entity_type=%s entity_id=%s is_host_remote=%r\n" % ( entity_host, entity_type, entity_id, is_host_remote ) )

# It is simpler to have an empty entity_host, if possible.
# CHAIS PAS. EN FAIT C EST LE CONTRAIRE, IL FAUT METTRE LE HOST
if not is_host_remote:
	entity_host = ""

# Each entity type ("process","file" etc... ) can have a small library
# of its own, for displaying a rdf node of this type.
# Beware that it is a bit unsafe.
entity_module = None
if entity_type != "":
	sys.stderr.write("PYTHONPATH="+os.environ['PYTHONPATH']+"\n")
	sys.stderr.write("sys.path="+str(sys.path)+"\n")
	try:
		entity_lib = "lib_entities.lib_entity_" + entity_type
		entity_module = importlib.import_module( ".lib_entity_" + entity_type, "lib_entities")
		sys.stderr.write("Loaded entity-specific library:"+entity_lib+"\n")
	except ImportError:
		sys.stderr.write("Info:Cannot find entity-specific library:"+entity_lib+"\n")
		entity_module = None

# Directory=/home/rchateau/Developpement/ReverseEngineeringApps/PythonStyle Type=process Id=5256 
relative_dir = lib_common.SourceDir(entity_type)
directory = lib_util.gblTopScripts + relative_dir

grph = rdflib.Graph()

rootNode = lib_util.RootUri()

################################################################################

g_infoCache = lib_infocache.InfoCache()

def DeserializeScriptInfoCached(key):
	# Equivalent to lib_common.DeserializeScriptInfo(key)
	global g_infoCache

	infoDict = g_infoCache.CachedValue(key)
	if infoDict != None:
		return infoDict
	else:
		return { "info" : "No cached info" }

################################################################################

# Temporary files created by Unix editors or others, littering the dev directories.
def IsTempFile(fil):
	# TODO: Uses endswith() because it is faster.
	if re.match( ".*~$", fil ):
		return True

	fileName, fileExtension = os.path.splitext(fil)
	if fileExtension in [".swp",".dot",".svg",".log"]:
		return True
	return False

# WHAT TO DO WITH THE HOST ???????
# This should not be the same scripts:
# Some "normal" scripts are able to use a hostname, but this is very rare.
# CgiEnv is able to say that. Also, this must be stored in the info cache.
# If we take the entity_id from CgiEnv without explicitely saying 
# that the current script can process the hostname, then it is an error.
# Also: This is where we need to "talk" to the other host ?
# And we must display the node of the host as seen from the local machine.

# This lists the scripts and generate RDF nodes.
def DirToMenu(grph,parentNode,curr_dir,relative_dir):
	# sys.stderr.write("curr_dir=%s\n"%(curr_dir))
	# In case there is nothing.
	dirs = None
	for path, dirs, files in os.walk(curr_dir):
		break

	# Maybe this class is not defined in our ontology.
	if dirs == None:
		# sys.stderr.write("No content in "+curr_dir)
		return

	for dir in dirs:
		# sys.stderr.write("dir=%s\n"%(dir))
		if dir == "__pycache__":
			continue

		full_sub_dir = curr_dir + "/" + dir
		currDirNode = lib_common.gUriGen.FileUri(full_sub_dir)
		grph.add( ( parentNode, pc.property_directory, currDirNode ) )

		DirToMenu(grph,currDirNode, full_sub_dir,relative_dir + "/" + dir)

	sub_path = path[ len(curr_dir) : ]
	for fil in files:
		if IsTempFile(fil):
			continue

		script_path = relative_dir + sub_path + "/" + fil

		# sys.stderr.write("DirToMenu encodedEntityId=%s\n" % encodedEntityId)
		if is_host_remote:
			genObj = lib_common.RemoteBox(entity_host)
		else:
			genObj = lib_common.gUriGen

		url_rdf = genObj.MakeTheNodeFromScript( script_path, entity_type, encodedEntityId )

		# TODO: Get the 'info' in an asynchronous loop, and later pick the values.
		# This is especially efficient when the cache is empty.
		infoDict = DeserializeScriptInfoCached(url_rdf)

		# sys.stderr.write("info=%s\n" % str(infoDict))

		# Is the script OK for this platform ?
		try:
			# Contains for example "lin" or "win"
			platform_regex = infoDict["platform_regex"]
			if platform_regex != "":
				platform_mtch = re.match( ".*" + platform_regex + ".*", sys.platform )
				if not platform_mtch:
					sys.stderr.write("No platform match with %s and %s\n" % ( sys.platform, platform_regex ) )
					continue
		except KeyError:
			# If not regular expression for checking platform, no problem.
			pass

		# If the entity is on another host, does this work on remote entities ?
		if is_host_remote:
			try:
				can_process_remote = infoDict["can_process_remote"]
			except:
				can_process_remote = False

			if not can_process_remote:
				sys.stderr.write("Script cannot work on remote entities: %s at %s\n" % ( entity_id , entity_host ) )
				continue

		# Here, we are sure that the script is added.
		# TODO: If no script is added, should not add the directory?
		rdfNode = rdflib.term.URIRef(url_rdf)
		grph.add( ( parentNode, pc.property_rdf_data, rdfNode ) )

		try:
			grph.add( ( rdfNode, pc.property_information, rdflib.Literal(infoDict["info"]) ) )
		except KeyError:
			pass
		# Adds an optional image URL. TODO: Do something with it.
		try:
			urlIcon = infoDict["url_icon"]
			if urlIcon != "":
				infoUrl = rdflib.term.URIRef( urlIcon )
				grph.add( ( rdfNode, pc.property_image, infoUrl ) )
		except KeyError:
			pass


################################################################################



# Si entity_type != "" mais entity_id == "", ca n'a pas de sens
# d'afficher les scripts du directory htbin/sources/<type>
# car on n'a pas d'id. En revanche, on pourrait afficher selectivement
# des scripts dans "top" qui affichent toutes les entites de ce type.
# Ca revient a selectionner certains scripts.
# On peut faire ca grossierement en filtrant sur le nom.
# Mais on voudrait en fait les afficher directement.
# On peut donc avoir des scripts appeles top/<type>.index.xyzw.py .
# Mais on voudrait en avoir plusieurs, eventuellement.


def CurrentUser():
	currProc = psutil.Process(os.getpid())
	return lib_entity_CIM_Process.PsutilProcToUser(currProc)

def AddDefaultScripts(grph,rootNode):
	nodeObjTypes = rdflib.term.URIRef( lib_util.uriRoot + '/objtypes.py' )
	grph.add( ( rootNode, pc.property_rdf_data_nolist, nodeObjTypes ) )

	# Gives a general access to WBEM servers.
	nodePortalWbem = rdflib.term.URIRef( lib_util.uriRoot + '/portal_wbem.py' )
	grph.add( ( rootNode, pc.property_rdf_data_nolist, nodePortalWbem ) )

	# Gives a general access to WMI servers.
	nodePortalWmi = rdflib.term.URIRef( lib_util.uriRoot + '/portal_wmi.py')
	grph.add( ( rootNode, pc.property_rdf_data_nolist, nodePortalWmi ) )

	currentNodeHostname = lib_common.gUriGen.HostnameUri( lib_common.hostName )
	grph.add( ( currentNodeHostname, pc.property_information, rdflib.Literal("Current host:"+lib_common.hostName) ) )
	grph.add( ( rootNode, pc.property_rdf_data_nolist, currentNodeHostname ) )

	currUsername = CurrentUser()
	currentNodeUser = lib_common.gUriGen.UserUri( currUsername )
	grph.add( ( currentNodeUser, pc.property_information, rdflib.Literal("Current user:"+currUsername) ) )
	grph.add( ( rootNode, pc.property_rdf_data_nolist, currentNodeUser ) )

################################################################################

if entity_id == "" and entity_type != "":
	# There is no entity to display.
	# TODO: Display a help text, or something.
	pass
else:
	if entity_module != None:
		entity_ids_arr = lib_util.EntityIdToArray( entity_type, entity_id )
		entity_module.AddInfo( grph, rootNode, entity_ids_arr )

	# N IMPORTE QUOI !!!!!!!!!!

	encodedEntityId=lib_util.EncodeUri(entity_id)
	#if is_host_remote:
	#	encodedEntityId = lib_util.RemoteEntityId( encodedEntityId, entity_host )
	
	# TODO: Plutot qu'attacher tous les sous-directory a node parent,
	# ce serait peut-etre mieux d'avoir un seul lien, et d'afficher
	# les enfants dans une table, un record etc...
	# OU: Certaines proprietes arborescentes seraient representees en mettant 
	# les objets dans des boites imbriquees: Tables ou records.
	# Ca peut marcher quand la propriete forme PAR CONSTRUCTION 
	# un DAG (Direct Acyclic Graph) qui serait alors traite de facon specifique.
	DirToMenu(grph,rootNode,directory,relative_dir)

# TODO: Use encodedEntityId if is_host_remote ? Or always ?

url_html = lib_util.Scriptize( '/entity_list.py', entity_type, entity_id )
htmlNode = rdflib.term.URIRef(url_html)
grph.add( ( rootNode, pc.property_html_data, htmlNode ) )


if entity_type != "":
	lib_entity_CIM_ComputerSystem.AddWbemWmiServers(grph,rootNode, entity_host, nameSpace, entity_type, entity_id)

# if entity_type == "":
AddDefaultScripts(grph,rootNode)

cgiEnv.OutCgiRdf(grph, "LAYOUT_RECT", [pc.property_directory,pc.property_rdf_data])

