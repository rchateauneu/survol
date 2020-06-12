#!/usr/bin/env python

import os, sys
from cgi import escape

# Minimalist CGI script
def TestCgi():
	print("Content-type: text/html")
	print("")
	print("<pre>")
	print("<strong>Python %s</strong>" % sys.version)
	keys = os.environ.keys()
	keys.sort()
	for k in keys:
		print("%s\t%s" % (escape(k), escape(os.environ[k])))
	print("</pre>")
	print("<br>GENUINE SCRIPT<br>")

if __name__ == '__main__':
	TestCgi()



