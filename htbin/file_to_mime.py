#!/usr/bin/python

# It receives as CGI arguments, the entity type which must be "file", and the filename.
# It must then return the content of the file, with the right MIME type,

import os
import sys
import re
import mimetypes

import cgi

import lib_common
import lib_util

cgiEnv = lib_common.CgiEnv()
should_be_file = cgiEnv.m_entity_type
fileName = cgiEnv.m_entity_id

mime_stuff = mimetypes.guess_type( fileName )

sys.stderr.write("MIME:%s\n" % str(mime_stuff) ) 

mime_type = mime_stuff[0]

# It could also be a binary stream.
if mime_type == None:
	mime_type = "text/html"

# read and write by chunks, so that it does not use all memory.
try:
	lib_util.CopyFile( mime_type, fileName, sys.stdout )
except Exception:
	exc = sys.exc_info()[1]
	lib_common.ErrorMessageHtml("Reading %s, caught:%s" % ( fileName, str(exc) ) )

sys.stdout.flush()
