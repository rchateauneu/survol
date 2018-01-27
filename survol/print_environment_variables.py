#!/usr/bin/python

# This is used for testing only.
# The output is plain HTML.

import os
import re
import cgi

# HTTP_HOST and SERVER_NAME and SERVER_PORT

def Main():
	arguments = cgi.FieldStorage()

	print("""Content-type: text/html

	<head>
	 <title>Environment variables</title>
	</head>
	<body>
	<table border="1">""")

	start = '..'
	sources = '/sources'
	rootdir = start + sources
	print("getcwd=" + os.getcwd() + "<br>")
	print("Dir=" + rootdir + "<br>")

	print("Cgi vars<br>")
	for key, value in os.environ.items():
		print( key + "=" + value + "<br>")
	print("Cgi vars end<br><br>")

	print("""
	</body></html>
	""")


if __name__ == '__main__':
	Main()

