#!/usr/bin/python

"""
Merge data from several sources
"""

import os
import sys
import time
import cgi
import lib_util
import lib_common

# This CGI script is called as a CGI script,
# and its parameters are input URLs in Base64UrlSafe format.
# It merges the input urls into a single RDF document,
# then transformed into DOT, then SVG by Graphviz, then displayed.
def Main():
	origReqUri = lib_util.RequestUri()

	# It initialises an implicit global object similar.
	# When in the mode of global merging, the method "cgiEnv.OutCgiRdf()" does not generate anything,
	# but simply stores the new cgiEnv in a global list..
	# The script loops on the URLs passed as CGI parameters.
	# The URLs are loaded and their content merged into the container lib_common.globalGraph
	lib_common.CgiEnvMergeMode()

	arguments = cgi.FieldStorage()

	# The display mode is read now, otherwise the CGI arguments are later destroyed, in this script.
	theMode = lib_util.GuessDisplayMode()
	DEBUG("theMode=%s",theMode)

	# Concatenation of error messages of each script.
	cumulatedError = ""

	# This logic might be needed in lib_client.py
	for urlfil in arguments.getlist("url"):
		# The parameters are coded in base64, although we leave the possibility not to encode them,
		# for compatibility with test scripts.

		complete_url = lib_util.Base64Decode(urlfil)

		DEBUG("complete_url=%s",complete_url)

		# Only the URL without the arguments.
		urlSplit = complete_url.split("?")
		urlNoArgs = urlSplit[0]
		if len(urlSplit) > 1:
			cgiQueryString = urlSplit[1]
		else:
			cgiQueryString = ""

		# The URL might be absolute or relative. Example:
		# "survol/sources_types/enumerate_CIM_Process.py?xid=."
		idxHtbin = urlNoArgs.find("sources_types/")
		if idxHtbin == -1:
			# This may be the main presentation page of a Survol, WMI or WBEM object. Example:
			# "http://127.0.0.1:80/Survol/survol/entity.py?xid=CIM_Process.Handle=640"
			survolPrefix = "survol/"
			idxSurvol = urlNoArgs.find(survolPrefix)
			if idxSurvol == -1:
				# TODO: This happens if the URL is a main presentation page of an object,
				# instead of a script: Something like "survol/entity.py/entity.py?xid=..."
				# This should be fixed but is not an issue.
				WARNING("merge: SHOULD NOT HAPPEN url=%s",complete_url)
				urlPathShort = "INVALID_MERGED_URL"
			else:
				# Just starts at the beginning of the script name: "entity.py", "entity_wmi.py", "entity_wbem.py".
				urlPathShort = urlNoArgs[idxSurvol + len(survolPrefix):]
		else:
			urlPathShort = urlNoArgs[idxHtbin:]

		# urlPathShort is the actual script to load.
		urlDirNam = os.path.dirname(urlPathShort)

		# The directory of the script is used to build a Python module name.
		moduNam = urlDirNam.replace("/",".")

		urlFilNam = os.path.basename(urlPathShort)

		DEBUG("urlPathShort=%s urlDirNam=%s moduNam=%s urlFilNam=%s",urlPathShort,urlDirNam,moduNam,urlFilNam)
		try:
			# argDir="sources_types.win32" urlFileNam="enumerate_top_level_windows.py"
			importedMod = lib_util.GetScriptModule(moduNam, urlFilNam)
		except Exception:
			errorMsg = sys.exc_info()[1]
			WARNING("Caught %s when loading moduNam=%s urlFilNam=%s",errorMsg,moduNam,urlFilNam)
			continue

		if not importedMod:
			cumulatedError = "merge_scripts.py Cannot import complete_url=%s" % (complete_url)
			continue

		try:
			# The entire URL must be "injected" so the parameters will be properly parsed,
			# when Main() call lib_util.RequestUri().
			# The script passed as CGI parameter, believes that it is loaded as a plain URL.
			urlUnquote = lib_util.urllib_unquote(complete_url)
			os.environ["REQUEST_URI"] = urlUnquote

			os.environ['SCRIPT_NAME'] = urlFilNam
			# "xid=EURO%5CLONL00111310@process:16580"
			os.environ['QUERY_STRING'] = cgiQueryString

			lib_common.ErrorMessageEnable(False)

			# This executes the script: The new nodes and links are merged in a global RDF container.
			importedMod.Main()
		except Exception:
			errorMsg = sys.exc_info()[1]
			WARNING("Caught %s when executing Main in moduNam=%s urlFilNam=%s",errorMsg,moduNam,urlFilNam)
			if cumulatedError != "":
				cumulatedError += " ; "
			cumulatedError += " url=" + urlNoArgs + " / "+urlFilNam + ":" + str(errorMsg)

			continue
		lib_common.ErrorMessageEnable(True)

	os.environ["REQUEST_URI"] = origReqUri

	# OutCgiRdf has been called by each script without writing anything,
	# but the specific parameters per script are stored inside.

	# Here, all the RDF nodes and links, loaded from each URL, and then merged in lib_common.globalGraph,
	# are then transformed into the chosen output format.
	lib_common.MergeOutCgiRdf(theMode,cumulatedError)

if __name__ == '__main__':
	Main()

