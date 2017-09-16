#!/usr/bin/python

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


# This is normally not used this way, but rather imported
# from cgi-bin/test.py which is not in GIT and does a plain import:

# #!/usr/bin/python
# from survol import scripts
# from survol.scripts import testcgi
#
# if __name__ == '__main__':
#	testcgi.TestCgi()
#
if __name__ == '__main__':
	TestCgi()



