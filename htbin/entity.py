#!/usr/bin/python

"""
RDF data sources
"""

import os
import re
import sys
import psutil
import rdflib
import importlib

from revlib import lib_util
from revlib import lib_common
from revlib.lib_properties import pc

import lib_entities.lib_entity_CIM_Process as lib_entity_CIM_Process
import lib_entities.lib_entity_CIM_ComputerSystem as lib_entity_CIM_ComputerSystem

paramkeyShowAll = "Show all scripts"

# This can process remote hosts because it does not call any script, just shows them.
cgiEnv = lib_common.CgiEnv(
				can_process_remote = True,
				parameters = { paramkeyShowAll : False })
entity_id = cgiEnv.m_entity_id
entity_host = cgiEnv.GetHost()
flagShowAll = int(cgiEnv.GetParameters( paramkeyShowAll ))

( nameSpace, entity_type, entity_namespace_type ) = cgiEnv.GetNamespaceType()

is_host_remote = not lib_util.IsLocalAddress( entity_host )

sys.stderr.write("entity: entity_host=%s entity_type=%s entity_id=%s is_host_remote=%r\n" % ( entity_host, entity_type, entity_id, is_host_remote ) )

# It is simpler to have an empty entity_host, if possible.
# CHAIS PAS. EN FAIT C EST LE CONTRAIRE, IL FAUT METTRE LE HOST
if not is_host_remote:
	entity_host = ""


# TODO: Temporarily until we do something more interesting, using the subtype.
# entity_type = entity_type.split(lib_util.CharTypesComposer)[0]


# Each entity type ("process","file" etc... ) can have a small library
# of its own, for displaying a rdf node of this type.
entity_module = None
if entity_type != "":
	sys.stderr.write("PYTHONPATH="+os.environ['PYTHONPATH']+"\n")
	sys.stderr.write("sys.path="+str(sys.path)+"\n")
	try:
		entity_lib = ".lib_entity_" + entity_type
		entity_module = importlib.import_module( entity_lib, "lib_entities")
		sys.stderr.write("Loaded entity-specific library:"+entity_lib+"\n")
	except ImportError:
		sys.stderr.write("Info:Cannot find entity-specific library:"+entity_lib+"\n")
		entity_module = None

# Directory=/home/rchateau/Developpement/ReverseEngineeringApps/PythonStyle Type=process Id=5256
# TODO: CharTypesComposer: Ca va retourner une liste de directory du plus bas au plus haut.
relative_dir = lib_common.SourceDir(entity_type)
directory = lib_util.gblTopScripts + relative_dir

grph = rdflib.Graph()

rootNode = lib_util.RootUri()

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


# TODO: CharTypesComposer
# Actuellement on parcourt toute l'arborescence et on affiche tous les scripts
# a partir d un directory. Ne pas descendre dans les sous-directories s'il y a un sous-type.
# Mais le faire quand meme si le decoupage est plutot un namespace.
# Comment a la fois utiliser des sous-directories comme types derives
# et comme namespaces ?
# Dans le directory principal, on peut n avoir que des names-spaces
# car un sous-type n a pas de sens. Et on affichera recursivement.
# Toutefois pour le directory des types,
# il faut descendre dans les namespaces mais pas dans les sous-types.
# En fait, pour travailleur naturellement, il faudrait inverser la hierarchie:
# Que les sous-types pointent vers les types.
# Peut-etre mettre dans le __init__.py du directory d'un sous-type,
# une reference vers le type de base. Ou bien se servir du nom ?
# Avec le separateur un sous-type contiendrait la liste de ses types de base ?

# On peut aussi donner une syntaxe specifique aux sous-directory namespaces,
# et DirToMenu ne descendra dans les sous-dir que si namespaces.
# Ou bien: Chaque directory contient dans le __init__.py
# une fonction qui dit si on peut afficher ou non:
# Cette fonction prend en parametre le entity_type, os.platform.
# Seul inconvenient:
#  - Il faut assigner un role a la classe de base, qui sert de directory de depart.
#  - La classe de base sert aussi pour la liste des parametres et les couleurs.
#  - Confusions classe de base et namespace: "oracle,table" et "mysql,table"
#    Valable pour les couleurs (Ca sert d avoir une couleur commune a tous
#    les objets d un meme namespace) mais pas pour les parametres evidemment.
#    Autre confusion si namespaces et classes de base ont la meme structure:
#    - Impossible d'apparier les hierarchies avec WBEM et WMI. Par exemple on pourrait
#    deriver localement de CIM_Process.
#    - Pourrait-on representer la hierarchie user/CIM_Account et user/LMI_Account ?
# Si on melange sous-types et namespaces, on descend toujours dans les dir des namespaces
# si la fonction de __init__.py le permet ? Probleme: le nom du type pourrait etre:
# "linux,file,dir" ou "windows,file,dir" ? ou "file,linux,symlink" ?
# Ou bien que "symlink" et on parcourerait toujours l arborescence ?
# Non: Le nom de la sous-classe doit toujours comporter le namespace.
# OU ALORS: Si namespace, c'est une hierachie a part:
# portable/sources_types/file/dir
# portable/sources_top/file/dir
# oracle/sources_types/table
# linux/sources_types/user
# windows_com/enumerate.Win32_Process
# Avantage: On deplace un namespace en copiant uniquement un directory.
# Et meme pourquoi ne pas reutiliser la syntaxe des sous-classes de WMI et WBEM ?




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
		# Might be generated by our Python interpreter.
		if dir == "__pycache__":
			continue

		full_sub_dir = curr_dir + "/" + dir
		currDirNode = lib_common.gUriGen.FileUri(full_sub_dir)
		grph.add( ( parentNode, pc.property_directory, currDirNode ) )

		DirToMenu(grph,currDirNode, full_sub_dir,relative_dir + "/" + dir)

	sub_path = path[ len(curr_dir) : ]
	for fil in files:
		if IsTempFile(fil) or fil == "__init__.py":
			continue

		if not fil.endswith(".py"):
			continue

		script_path = relative_dir + sub_path + "/" + fil

		# sys.stderr.write("DirToMenu encodedEntityId=%s\n" % encodedEntityId)
		if is_host_remote:
			genObj = lib_common.RemoteBox(entity_host)
		else:
			genObj = lib_common.gUriGen

		url_rdf = genObj.MakeTheNodeFromScript( script_path, entity_type, encodedEntityId )

		#  script_path = "/sources_top/Databases/mysql_processlist"
		# importlib.import_module( ".lib_entity_" + entity_type, "lib_entities")
		try:
			# TODO: IT DOES NOT START FROM "/revlib". DIFFICULTY WITH PYTHONPATH.
			argFil = "." + fil[:-3]
			argDir = ( relative_dir + sub_path ).replace("/",".")[1:]
			sys.stderr.write("argFil=%s argDir=%s\n" % ( argFil, argDir ) )
			importedMod = importlib.import_module(argFil, argDir )
		except ImportError:
			exc = sys.exc_info()[1]
			sys.stderr.write("Cannot import=%s. Caught: %s\n" % (script_path, str(exc) ) )
			continue
		except NameError:
			exc = sys.exc_info()[1]
			sys.stderr.write("Other error: Cannot import=%s. Caught: %s\n" % (script_path, str(exc) ) )
			continue

		# Show only scripts which want to be shown.
		if not flagShowAll:
			try:
				isUsable = importedMod.Usable(entity_type,entity_ids_arr)
				if not isUsable:
					continue
			except AttributeError:
				pass

		# If the entity is on another host, does this work on remote entities ?
		if is_host_remote:
			try:
				# Script can be used on a remote entity.
				can_process_remote = importedMod.CanProcessRemote() # infoDict["can_process_remote"]
			except AttributeError:
				can_process_remote = False

			if not can_process_remote:
				sys.stderr.write("Script cannot work on remote entities: %s at %s\n" % ( entity_id , entity_host ) )
				continue

		# Here, we are sure that the script is added.
		# TODO: If no script is added, should not add the directory?
		rdfNode = rdflib.term.URIRef(url_rdf)
		grph.add( ( parentNode, pc.property_rdf_data, rdfNode ) )

		try:
			docModu = importedMod.__doc__
			maxLen = 30
			if len(docModu) > maxLen:
				docModu = docModu[0:maxLen] + "..."
		except:
			# If no doc available, just transform the file name.
			docModu = fil[:-3].replace("_"," ").capitalize()
		grph.add( ( rdfNode, pc.property_information, rdflib.Literal(docModu) ) )

		# Adds an optional image URL. TODO: Do something with it.
		try:
			urlIcon = importedMod.Icon
			if urlIcon != "":
				infoUrl = rdflib.term.URIRef( urlIcon )
				grph.add( ( rdfNode, pc.property_image, infoUrl ) )
		except AttributeError:
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

	currentNodeHostname = lib_common.gUriGen.HostnameUri( lib_util.currentHostname )
	grph.add( ( currentNodeHostname, pc.property_information, rdflib.Literal("Current host:"+lib_util.currentHostname) ) )
	grph.add( ( rootNode, pc.property_rdf_data_nolist, currentNodeHostname ) )

	currUsername = CurrentUser()
	currentNodeUser = lib_common.gUriGen.UserUri( currUsername )
	grph.add( ( currentNodeUser, pc.property_information, rdflib.Literal("Current user:"+currUsername) ) )
	grph.add( ( rootNode, pc.property_rdf_data_nolist, currentNodeUser ) )

################################################################################

if entity_id == "" and entity_type != "":
	# There is no entity to display, but a type is given.
	# TODO: Display help about this entity type.
	pass
else:
	if entity_module != None:
		entity_ids_arr = lib_util.EntityIdToArray( entity_type, entity_id )
		entity_module.AddInfo( grph, rootNode, entity_ids_arr )
	else:
		entity_ids_arr = None

	encodedEntityId=lib_util.EncodeUri(entity_id)

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

