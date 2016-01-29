#!/usr/bin/python

import os
import re
import sys
import rdflib

import lib_common
import lib_entities.lib_entity_file
import lib_util
from lib_properties import pc

cgiEnv = lib_common.CgiEnv("Directory")
filNam = cgiEnv.GetId()
sys.stderr.write("filNam=%s\n" % filNam )

# Maybe this is a disk name, on Windows, such as "A:", "C:" etc...
# If so, we had a slash at the end, otherwise it does not work.
if ( "win" in sys.platform ) and re.match( "^[a-zA-Z]:$", filNam ):
	filNam += "/"


# filNode = lib_util.EntityUri('file', filNam )
filNode = lib_common.gUriGen.FileUri(filNam )

grph = rdflib.Graph()

if filNam != '/':
	# TODO: Does it work on Windows ???
	splitdir = filNam.split('/')
	topdir = '/'.join( splitdir[:-1] )
	if topdir != "":
		sys.stderr.write("topdir=%s\n"%(topdir))
		topdirEncoded=lib_util.EncodeUri(topdir)
		# topdirNode = lib_util.EntityUri('file', topdirEncoded )
		topdirNode = lib_common.gUriGen.FileUri(topdir )
		grph.add( ( topdirNode, pc.property_directory, filNode ) )

		url_mime = lib_util.Scriptize('/sources_types/file/file_directory.py', "file", topdirEncoded )
		grph.add( ( topdirNode, pc.property_rdf_data_nolist, rdflib.term.URIRef(url_mime) ) )

if os.path.isdir( filNam ):
	sys.stderr.write("filNam=%s\n"%(filNam))

	# In case we do not loop at all.
	dirs = None
	for subdir, dirs, files in os.walk(filNam):
		break

	if dirs == None:
		lib_common.ErrorMessageHtml("No files in:"+filNam)

	filNam_slash = filNam + "/"
	for dir in dirs:
		fullDirPath = filNam_slash + dir
		subdirEncoded=lib_util.EncodeUri(fullDirPath)
		# subdirNode = lib_util.EntityUri('file', subdirEncoded )
		subdirNode = lib_common.gUriGen.FileUri( fullDirPath )
		grph.add( ( filNode, pc.property_directory, subdirNode ) )

		url_mime = lib_util.Scriptize('/sources_types/file/file_directory.py', "file", lib_util.EncodeUri(subdirEncoded) )
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
		# subfileEncoded=lib_util.EncodeUri(fullFilePath)
		# OK WinXP: On remplace d'abord le ampersand, et on encode ensuite,
		# car le remplacement ne marche pas dans l'autre sens.
		# subfilNode = lib_util.EntityUri('file', lib_util.EncodeUri( fullFilePath.replace("&","&amp;" ) ) )
		subfilNode = lib_common.gUriGen.FileUri( fullFilePath.replace("&","&amp;" ) )

		grph.add( ( filNode, pc.property_directory, subfilNode ) )

		lib_entities.lib_entity_file.AddStat( grph, subfilNode, fullFilePath )
		lib_entities.lib_entity_file.AddHtml( grph, subfilNode, fullFilePath )

cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT", [pc.property_directory] )
# cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT", [] )


