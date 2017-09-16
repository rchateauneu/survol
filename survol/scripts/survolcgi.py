#!/usr/bin/python

import os, sys
from cgi import escape

# The intent of this script is to be run as a CGI script, calling the various scripts of survol,
# as modules. It is necessary for some HTTP server setups where it is not possible
# to call a Python program as CGI script.
#
# It might be compiled into an exe, or renamed into xxx.cgi.
# It works for example this way:
#
# http://127.0.0.1:8000/survol.cgi?script=sources_types/cgi_arp_async.py&xid=.
# http://127.0.0.1:8000/survol.cgi?script=entity.py&xid=CIM_ComputerSystem.Name=192.168.0.13
#
# The CGI parameter "script" is the Python module to import.
# The other parameters are the CGI params this Python module expects.
#
# The URLs created by the Python code must take into account this new URL structure.
# Probably, all the parsing of URLs will have to be reviewed.

# Minimalist CGI script
def SurvolCgi():
	print("Content-type: text/html")
	print("")
	print("<pre>")
	print("<strong>Python %s</strong>" % sys.version)
	keys = os.environ.keys()
	keys.sort()
	for k in keys:
		print("%s\t%s" % (escape(k), escape(os.environ[k])))
	print("</pre>")


if __name__ == '__main__':
    SurvolCgi()



