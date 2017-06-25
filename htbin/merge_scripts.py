#!/usr/bin/python

import os
import sys
import time
import cgi
import lib_util
import lib_common

try:
	from urllib import unquote
	from urlparse import urlparse
except ImportError:
	from urllib.parse import unquote
	from urllib.parse import urlparse

# This CGI script is called as a CGI script,
# and its parameters are input URLs in Base64UrlSafe format.
# It merges the input urls into a single RDF document,
# then transformed into DOT, then SVG by Graphviz, then displayed.

origReqUri = lib_util.RequestUri()

# There is only one cgiEnv and "cgiEnv.OutCgiRdf()" does not generate anything.
lib_common.CgiEnvMergeMode()

arguments = cgi.FieldStorage()

for urlfil in arguments.getlist("url"):
	# The parameters are coded in base64, although we leave the possibility not to encode them,
	# for compatibility with test scripts.

	# "htbin/sources_types/enumerate_CIM_Process.py?xid=."
	complete_url = urlfil
	complete_url = lib_util.Base64Decode(urlfil)

	sys.stderr.write("complete_url=%s\n"%complete_url)

	# Only the URL without the arguments.
	urlSplit = complete_url.split("?")
	urlNoArgs = urlSplit[0]
	if len(urlSplit) > 1:
		cgiQueryString = urlSplit[1]
	else:
		cgiQueryString = ""

	#if urlNoArgs.startswith("http://"):
	#	# url="http://127.0.0.1:8000/htbin/sources_types/oracle/db/oracle_db_schemas.py?xid=oracle/db.Db%3DXE"
	#	# uprs = urlparse(url)
	#	# ParseResult(scheme='http', netloc='127.0.0.1:8000', path='/htbin/sources_types/oracle/db/oracle_db_schemas.py', params='', query='xid=oracle/db.Db%3DXE', fragment='')
	#	urlParsed = urlparse(urlNoArgs)
#
#		# The CGI arguments will be injected in the cgiEnv object before calling the script.
	#	urlPath = urlParsed.path
	#	urlPathShort = urlPath[7:]
	#elif complete_url.startswith("htbin/"):
	#	urlPath = urlNoArgs
	#	urlPathShort = urlPath[6:]
	#else:
	#	sys.stderr.write("SHOULD NOT HAPPEN url=%s\n"%complete_url)


	idxHtbin = urlNoArgs.find("/htbin/")
	if idxHtbin == -1:
		sys.stderr.write("SHOULD NOT HAPPEN url=%s\n"%complete_url)
	urlPathShort = urlNoArgs[idxHtbin+7:]

	urlDirNam = os.path.dirname(urlPathShort)
	moduNam = urlDirNam.replace("/",".")

	urlFilNam = os.path.basename(urlPathShort)

	sys.stderr.write("urlPathShort=%s urlDirNam=%s moduNam=%s urlFilNam=%s\n"%(urlPathShort,urlDirNam,moduNam,urlFilNam))
	try:
		# argDir="sources_types.win32" urlFileNam="enumerate_top_level_windows.py"
		importedMod = lib_util.GetScriptModule(moduNam, urlFilNam)
	except Exception:
		errorMsg = sys.exc_info()[1]
		sys.stderr.write("Caught %s when loading moduNam=%s urlFilNam=%s\n"%(errorMsg,moduNam,urlFilNam))
		continue

	try:
		# The entire URL must be "injected" so the parameters will be properly parsed,
		# when Main() call lib_util.RequestUri().
		urlUnquote = unquote(complete_url)
		os.environ["REQUEST_URI"] = urlUnquote

		os.environ['SCRIPT_NAME'] = urlFilNam
		# "xid=EURO%5CLONL00111310@process:16580"
		os.environ['QUERY_STRING'] = cgiQueryString

		importedMod.Main()
	except Exception:
		errorMsg = sys.exc_info()[1]
		sys.stderr.write("Caught %s when executing Main in moduNam=%s urlFilNam=%s\n"%(errorMsg,moduNam,urlFilNam))
		continue

os.environ["REQUEST_URI"] = origReqUri

# Default value for output mode.
try:
	theMode = arguments["mode"].value
except KeyError:
	theMode = "svg"

theMode = lib_common.GuessDisplayMode()

# OutCgiRdf has been called by each script without writing anything,
# but the specific parameters per script are stored inside.
lib_common.MergeOutCgiRdf(theMode)

