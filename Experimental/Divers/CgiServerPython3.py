#!/usr/bin/python

# To run this, in msdos-like command box:
# cd PythonStyle
# python Divers\CgiServerPython3.py
# URL is: http://127.0.0.1:8080/htbin/entity.py

import http.server
import http.server

# There is a known bug in some versions.
# http://bugs.python.org/issue21323
# CGI HTTP server not running scripts from subdirectories
# Otherwise just return "/htbin"
import os
import sys

# This does not work with Python 3.4 and fails with the message:
# CGI script is not a plain file ('/htbin/sources').
# http://bugs.python.org/issue21323
# There is not fix except upgrading.
def AllSubDirs(cgidir):
	ret = ["/htbin"]
	# return ret
	for path,dirs,files in os.walk(cgidir):
		for dir in dirs:
			if dir in ["__pycache__", "Debug"]:
				continue
			appdir = "\\" + path + "\\" + dir
			appdir = appdir.replace( "\\", "/")
			print("appdir="+appdir)
			ret.append( appdir )
	
	return ret

global_cgi_dirs = AllSubDirs( "htbin" )

class Handler(http.server.CGIHTTPRequestHandler):
    cgi_directories = global_cgi_dirs

server = http.server.HTTPServer(("",8080),Handler)
server.serve_forever()