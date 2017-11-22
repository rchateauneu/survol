#!/usr/bin/python

"""Display MIME content"""

# It receives as CGI arguments, the entity type which is "HttpUrl_MimeDocument", and the filename.
# It must then return the content of the file, with the right MIME type,

import os
import sys
import re
import cgi
import lib_mime
import lib_common
import lib_util

def Main():
	cgiEnv = lib_common.CgiEnv()

	# The class "HttpUrl_MimeDocument" is not defined yet but it does not matter.
	# Will create CSS files.
	fileName = cgiEnv.GetId()

	mime_stuff = lib_mime.FilenameToMime( fileName )

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

# TOOD: Some files in /proc filesystem, on Linux, could be displayed
# not simply as plain text files, but with links replacing text.
# Example:
#
#  /proc/diskstats
#  11       0 sr0 0 0 0 0 0 0 0 0 0 0 0
#   8       0 sda 153201 6874 4387154 1139921 637311 564765 40773896 13580495 0 2700146 14726473
#
# /proc/devices
#Character devices:
#  4 /dev/vc/0
#  4 tty
#
#  ... etc ...