#!/usr/bin/python

import cgi
import cgitb
cgitb.enable()

import os
import sys
from cgi import escape

sys.path.append("survol")

import lib_util
import lib_uris

# This is used only in the very specific case of the installation on a dedicated
# WEB server such as OVH, and should be deprecated.

# The intent of this script is to be run as a CGI script, calling the various scripts of survol,
# as modules. It is necessary for some HTTP server setups where it is not possible
# to call a Python program as CGI script.
#
# It can only be in the "survol" directory because Python uses the current directory as search path
# when importing modules, and submodules, even when they are not installed.
# Thus, it is not necessary to change PYTHONPATH, and this CGI script can be used in OVH in mutualised mode.
#
# It is called from OVH cgi-bin/survolcgi.py script, this way:
# #!/usr/bin/python
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
def SurvolTestCgi():
	print("Content-type: text/html")
	print("")
	print("<pre>")
	print("<strong>Python %s</strong>" % sys.version)
	keys = os.environ.keys()
	keys.sort()
	for k in keys:
		print("%s\t%s" % (escape(k), escape(os.environ[k])))
	print("</pre>")

def SurvolCgi():

	# We must change the prefix of all displayed links so thatr instead of being "dirname/script.py?xid=abc",
	# they will be "survolcgi.py?script=dirname/script.py?xid=abc"
	# See the function lib_uris.MakeTheNodeFromScript()
	lib_util.uriRoot = lib_util.HttpPrefix() + "/cgi-bin/survol/survolcgi.py?script="
	lib_util.xidCgiDelimiter = "&amp;amp;xid="

	arguments = cgi.FieldStorage()

	try:
		# The script has to be coded because it contains slashes, its own CGI arguments etc...
		scriptB64 = arguments["script"].value

		# Should have the form "entity.py?xid=..." or "sources_types/enumerate_CIM_Process.py" etc...
		# scriptPlain = lib_util.Base64Decode(scriptB64)
		scriptPlain = scriptB64
	except KeyError:
		scriptPlain = "entity.py"
		print("\nForce script to entity.py\n")
		# In case there are several mode arguments,
		# hardcode to "info". Consequence of a nasty Javascript bug.


	scriptSplit = scriptPlain.split('/')

	# In case it would start by a slash.
	if (scriptSplit[0] == "") and (len(scriptSplit) > 1):
		scriptSplit = scriptSplit[1:]

	if len(scriptSplit) > 1:
		currentModule = ".".join(scriptSplit[:-1])
		scriptFileName = scriptSplit[-1]
	else:
		currentModule = ""
		scriptFileName = scriptSplit[0]

	# Maybe there are CGI arguments, we get rid of them.
	# scriptFileName=merge_scripts.py?url=aHR0cDovL3d3dy5...
	scriptFileName = scriptFileName.split("?")[0]

	#currentModule = ""
	#scriptFileName = "entity.py"

	# CA MARCHE
	#currentModule = "sources_types"
	#scriptFileName = "enumerate_CIM_Process.py"

	sys.stderr.write("currentModule=%s scriptFileName=%s\n"%(currentModule,scriptFileName))

	# This works with currentModule="survol" and scriptFileName="entity.py" . REALLY ???
	impMod = lib_util.GetScriptModule(currentModule, scriptFileName)


	#COMMENT PASSER LES ARGUMENTS ???
	#ESTE QUE CA MNARCHE EN LOCAL ??/
	#REtster a fond car on etait fatigue.

	if impMod:
		impMod.Main()
	else:
		print("\n\nCannot get mode:currentModule=%s scriptFileName=%s\n"%(currentModule,scriptFileName))

if __name__ == '__main__':
    SurvolCgi()



