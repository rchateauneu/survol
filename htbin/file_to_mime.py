#!/usr/bin/python

"""Display MIME content"""

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

fileName = cgiEnv.GetId()

mime_stuff = mimetypes.guess_type( fileName )

sys.stderr.write("fileName=%s MIME:%s\n" % (fileName, str(mime_stuff) ) )

mime_type = mime_stuff[0]

# It could also be a binary stream.
if mime_type == None:
	lib_common.ErrorMessageHtml("No mime type for %s"%fileName)

try:
	# Read and write by chunks, so that it does not use all memory.
	lib_util.CopyFile( mime_type, fileName, sys.stdout )
except Exception:
	exc = sys.exc_info()[1]
	lib_common.ErrorMessageHtml("Reading %s, caught:%s" % ( fileName, str(exc) ) )

sys.stdout.flush()

