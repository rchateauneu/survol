#!/usr/bin/python

"""Display MIME content"""

# It receives as CGI arguments, the entity type which must be "file", and the filename.
# It must then return the content of the file, with the right MIME type,

import os
import sys
import re
import mimetypes

import cgi

import lib_common
import lib_util

def Main():
	cgiEnv = lib_common.CgiEnv()

	fileName = cgiEnv.GetId()

	mime_stuff = mimetypes.guess_type( fileName )

	sys.stderr.write("fileName=%s MIME:%s\n" % (fileName, str(mime_stuff) ) )

	mime_type = mime_stuff[0]

	# It could also be a binary stream.
	if mime_type == None:
		lib_common.ErrorMessageHtml("No mime type for %s"%fileName)

	# TODO: Find a solution for JSON files such as:
	# "No mime type for C:\Users\rchateau\AppData\Roaming\Mozilla\Firefox\Profiles\gciw4sok.default/dh-ldata.json"

	try:
		# Read and write by chunks, so that it does not use all memory.
		# lib_util.CopyFile( mime_type, fileName, sys.stdout )
		# Tested with Python3.
		# TODO: Change this with WSGI.
		lib_util.CopyFile( mime_type, fileName )

	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Reading %s, caught:%s" % ( fileName, str(exc) ) )

if __name__ == '__main__':
	Main()

