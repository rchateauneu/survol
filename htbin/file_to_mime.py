#!/usr/bin/python

# It receives as CGI arguments, the entity type which must be "file", and the filename.
# It must then return the content of the file, with the right MIME type,

import os
import sys
import re
import mimetypes

import cgi
import SimpleHTTPServer

import lib_common
import lib_util


cgiEnv = lib_common.CgiEnv()
should_be_file = cgiEnv.m_entity_type
# fileName = cgiEnv.m_entity_id
fileName = cgiEnv.GetId()

# fileName = "C://Users/rchateau/AlsaSeveralSoundCards.txt"

mime_stuff = mimetypes.guess_type( fileName )

sys.stderr.write("fileName=%s MIME:%s\n" % (fileName, str(mime_stuff) ) )

mime_type = mime_stuff[0]

# It could also be a binary stream.
if mime_type == None:
	mime_type = "text/html"


if True: # False:
	# This works for text files but not the rest, when this is not a text file.
	# Maybe encoding problems.
	try:
		# Read and write by chunks, so that it does not use all memory.
		lib_util.CopyFile( mime_type, fileName, sys.stdout )
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Reading %s, caught:%s" % ( fileName, str(exc) ) )

	sys.stdout.flush()
else:
	pass
	#Servir le fichier avec SimpleHTTPServer
	#On va d abord tester avec du texte.
	# TODO: ON FAIT DIFFEREMENT:
	# http://www.2ality.com/2014/06/simple-http-server.html
	# SimpleHTTPServer et ca va marcher aussi pour les directory.
	# Eventuellement on va le customiser en fonction du type.

	# TODO: DEPENDING ON THE TYPE OF THE FILE, WE COULD EXTRACT SOME ENTITIES ?
	# - /proc file system.
	# - Symbolic links.

	# On le fera aussi pour les directory, en ajoutant des icones MIME et des liens
	# vers nos entites.
	# TODO: Ca va aussi permettre d'explorer les pseudos-fichiers comme "/proc" !!!!!!!

