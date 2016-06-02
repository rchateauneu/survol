#!/usr/bin/python

"""
Files in directory
"""

import os
import re
import sys
import rdflib
import lib_uris
import lib_common
import lib_entities.lib_entity_file
import lib_util
from lib_properties import pc

# If this is not a directory, should not be displayed.
def Usable(entity_type,entity_ids_arr):
	if not lib_util.UsableWindows(entity_type,entity_ids_arr):
		return False
	dirNam = entity_ids_arr[0]
	return os.path.isdir(dirNam)

# This can work only if the HTTP server allows so.
# Purely experimental.
# Apache option:
# Alias /Maison "C:/Users/rchateau"
# <Directory "C:/Users/rchateau/>
# 	Options +Indexes
# </Directory>
# Il faudrait plutot un script externe qui lise la configuraton Apache.
# fullDirPath=C:\\/Users/rchateau/FiatLux/ChapelleStansted
#
# TODO: Integrer un serveur HTML qui affiche le directory !!!!
# TODO: C EST MEME QUELQUE CHOSE Qu ON PEUT FAIRE SYSTEMATIQUEMENT.
# TODO: ON PROPOSE DE PASSER EN HTML.
# TODO: DIFFERENT DE L AFFICHAGE DU RDF EN HTML.
# TODO: C EST PLUTOT SE SIMPLIFIER LA VIE SI HTML EST PLUS ADEQUAT.
# TODO: MAIS DANS LE HTML GENERE, ON REMET NOS LIENS SVG.
# TODO: CA N EMPECHE PAS D AVOIR PLUSIEURS LIENS CAR ON PEUT AVOIR DES SITES SPECIALISES
# TODO: SELON L OBJET.
#
# NON !!! On va utiliser SimpleHttpServer, voir file_to_mime.py
# Mais on s'en fiche, on veut donner la priorite au RDF.
#
# Icones de Apache: http://127.0.0.1/icons/folder.gif
# http://127.0.0.1/icons/sound2.gif
#
# TODO: THIS IS BROKEN. DOES NOT MAKE SENSE !
def UrlDirectory( fullDirPath ):
	# sys.stderr.write("UrlDirectory fullDirPath=%s\n" % fullDirPath)
	dirPrefix = "C://Users/rchateau"
	if fullDirPath.startswith( dirPrefix ):
		shortPath = fullDirPath[ len(dirPrefix) : ]
		shortpathclean = shortPath.replace("&","&amp;" )
		dirUrl = "http://127.0.0.1/Maison/" + shortpathclean
		return rdflib.term.URIRef(dirUrl)
	return None


# Used only here.
def UriDirectoryDirectScript(dirNam):
	return lib_uris.gUriGen.UriMakeFromScript(
		'/sources_types/file/file_directory.py',
		"file", # TODO: NOT SURE: lib_util.ComposeTypes("file","dir"),
		lib_util.EncodeUri(dirNam) )


def Main():
	cgiEnv = lib_common.CgiEnv()
	filNam = cgiEnv.GetId()

	# entity_host = cgiEnv.GetHost()

	# Maybe this is a disk name, on Windows, such as "A:", "C:" etc...
	if lib_util.isPlatformWindows :
		# Remove the trailing backslash.
		if re.match( r"^[a-zA-Z]:\\$", filNam ):
			filNam = filNam[:2]
		# Add a slash at the end, otherwise it does not work.
		if re.match( "^[a-zA-Z]:$", filNam ):
			filNam += "/"

	sys.stderr.write("filNam=%s\n" % filNam )

	filNode = lib_common.gUriGen.FileUri(filNam )

	grph = rdflib.Graph()

	if filNam != '/':
		# TODO: Does it work on Windows ???
		splitdir = filNam.split('/')
		topdir = '/'.join( splitdir[:-1] )
		if topdir != "":
			# sys.stderr.write("topdir=%s\n"%(topdir))
			topdirNode = lib_common.gUriGen.DirectoryUri(topdir )
			grph.add( ( topdirNode, pc.property_directory, filNode ) )

			url_mime = UriDirectoryDirectScript( topdir )
			grph.add( ( topdirNode, pc.property_rdf_data_nolist, rdflib.term.URIRef(url_mime) ) )

	if os.path.isdir( filNam ):
		# sys.stderr.write("filNam=%s\n"%(filNam))

		# In case we do not loop at all.
		dirs = None
		for subdir, dirs, files in os.walk(filNam):
			break

		if dirs == None:
			lib_common.ErrorMessageHtml("No files in:"+filNam)

		filNam_slash = filNam + "/"
		for dir in dirs:
			fullDirPath = filNam_slash + dir
			subdirNode = lib_common.gUriGen.DirectoryUri( fullDirPath.replace("&","&amp;" ) )
			grph.add( ( filNode, pc.property_directory, subdirNode ) )

			url_dir_node = UrlDirectory( fullDirPath )
			if not url_dir_node is None:
				grph.add( ( subdirNode, pc.property_html_data, url_dir_node ) )

			url_mime = UriDirectoryDirectScript(fullDirPath)
			grph.add( ( subdirNode, pc.property_rdf_data_nolist, rdflib.term.URIRef(url_mime) ) )

			# On peut ajouter des liens en rdf_data mais leur nom est normalement une "info".
			# Donc en affichage horizontal, il faut aussi virer ce sous-noeud.
			# C est vraiment un cas special car le noeud "info" du noed "rdf_data" doit etre utilise
			# comme titre de l'url, et il doit y en avoir un et un seul.
			# Que se passe--til si le noeud rdf_data pointe vers d'autres noeuds?
			# On pourrait avoir propriete=rdf_data mais la valeur serait un literal ?

		# TODO: Quand c'est un script, verifier qu'on peut l'executer !!!
		for file in files:
			fullFilePath = filNam_slash+file
			# OK WinXP: On remplace d'abord le ampersand, et on encode ensuite, car le remplacement ne marche pas dans l'autre sens.
			subfilNode = lib_common.gUriGen.FileUri( fullFilePath.replace("&","&amp;" ) )

			grph.add( ( filNode, pc.property_directory, subfilNode ) )

			lib_entities.lib_entity_file.AddStat( grph, subfilNode, fullFilePath )
			lib_entities.lib_entity_file.AddHtml( grph, subfilNode, fullFilePath )

	cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT", [pc.property_directory] )
	# cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT", [] )

if __name__ == '__main__':
	Main()


