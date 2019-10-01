#!/usr/bin/env python

# This is used for testing only.
# The output is plain HTML.

import os
import re
import cgi
import sys

# HTTP_HOST and SERVER_NAME and SERVER_PORT
# BEWARE: This does not work with WSGI.

def Main():
	arguments = cgi.FieldStorage()

	def OutStr(a_str):
		try:
			sys.stdout.write(a_str.decode())
		except Exception as exc:
			sys.stderr.write(__file__ + " Caught" + str(exc))

	OutStr("Content-type: text/html\n\n")
	OutStr("<head><title>Environment variables</title></head>\n")
	OutStr("<body>\n")
	OutStr("<table border=\"1\">")

	def add_line(key, value):
		OutStr("<tr><td>%s</td><td>%s</td></tr>\n" % (key, value))

	start = '..'
	sources = '/sources'
	rootdir = start + sources
	add_line("getcwd", os.getcwd())
	add_line("rootdir", rootdir)

	for key, value in os.environ.items():
		add_line(key, value)

	OutStr("</table>\n")
	OutStr("</body>\n")
	OutStr("</html>\n")

if __name__ == '__main__':
	Main()

