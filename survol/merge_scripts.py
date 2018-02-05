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

	# There is only one cgiEnv and "cgiEnv.OutCgiRdf()" does not generate anything.
	lib_common.CgiEnvMergeMode()

	arguments = cgi.FieldStorage()

	# The display mode is read now, otherwise the CGI arguments are later destroyed, in this script.
	theMode = lib_util.GuessDisplayMode()
	sys.stderr.write("merge_scripts.py theMode=%s\n"%(theMode))

	# Concatenation of error messages of each script.
	cumulatedError = ""

	for urlfil in arguments.getlist("url"):
		# The parameters are coded in base64, although we leave the possibility not to encode them,
		# for compatibility with test scripts.

		complete_url = lib_util.Base64Decode(urlfil)

		sys.stderr.write("complete_url=%s\n"%complete_url)

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
				sys.stderr.write("merge: SHOULD NOT HAPPEN url=%s\n"%complete_url)
				urlPathShort = "INVALID_MERGED_URL"
			else:
				# Just starts at the beginning of the script name: "entity.py", "entity_wmi.py", "entity_wbem.py".
				urlPathShort = urlNoArgs[idxSurvol + len(survolPrefix):]
		else:
			urlPathShort = urlNoArgs[idxHtbin:]

		# urlPathShort is the actual script to load.
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

		if not importedMod:
			cumulatedError = "merge_scripts.py Cannot import complete_url=%s" % (complete_url)
			continue

		try:
			# The entire URL must be "injected" so the parameters will be properly parsed,
			# when Main() call lib_util.RequestUri().
			urlUnquote = lib_util.urllib_unquote(complete_url)
			os.environ["REQUEST_URI"] = urlUnquote

			os.environ['SCRIPT_NAME'] = urlFilNam
			# "xid=EURO%5CLONL00111310@process:16580"
			os.environ['QUERY_STRING'] = cgiQueryString

			lib_common.ErrorMessageEnable(False)
			importedMod.Main()
		except Exception:
			errorMsg = sys.exc_info()[1]
			sys.stderr.write("Caught %s when executing Main in moduNam=%s urlFilNam=%s\n"%(errorMsg,moduNam,urlFilNam))
			if cumulatedError != "":
				cumulatedError += " ; "
			cumulatedError += " url=" + urlNoArgs + " / "+urlFilNam + ":" + str(errorMsg)

			continue
		lib_common.ErrorMessageEnable(True)

	os.environ["REQUEST_URI"] = origReqUri

	# OutCgiRdf has been called by each script without writing anything,
	# but the specific parameters per script are stored inside.

	# TESTER AVEC CA:
	# http://127.0.0.1:8000/survol/merge_scripts.py?url=aHRiaW4vc291cmNlc190eXBlcy9hZGRyL3NvY2tldF9ob3N0LnB5P3hpZD1hZGRyLklkJTNEMTkyLjE2OC4xLjg4JTNBc3No&url=aHRiaW4vc291cmNlc190eXBlcy9DSU1fQ29tcHV0ZXJTeXN0ZW0vaG9zdG5hbWVfbm1hcC5weT94aWQ9Q0lNX0NvbXB1dGVyU3lzdGVtLk5hbWUlM0RVbmtub3duLTMwLWI1LWMyLTAyLTBjLWI1LTI&url=aHRiaW4vc291cmNlc190eXBlcy9hZGRyL3NvY2tldF9ob3N0LnB5P3hpZD1hZGRyLklkJTNEMTkyLjE2OC4xLjg4JTNBc3ZybG9j&url=aHRiaW4vZW50aXR5LnB5P3hpZD1zbWJzaHIuSWQ9Ly8vL1dETXlDbG91ZE1pcnJvci9yY2hhdGVhdQ&url=aHRiaW4vc291cmNlc190eXBlcy9DSU1fQ29tcHV0ZXJTeXN0ZW0vY29ubmVjdGVkX3NvY2tldHMucHk_eGlkPUNJTV9Db21wdXRlclN5c3RlbS5OYW1lJTNEVW5rbm93bi0zMC1iNS1jMi0wMi0wYy1iNS0y&url=aHRiaW4vc291cmNlc190eXBlcy9DSU1fQ29tcHV0ZXJTeXN0ZW0vaG9zdG5hbWVfbm1hcC5weT94aWQ9Q0lNX0NvbXB1dGVyU3lzdGVtLk5hbWUlM0RVbmtub3duLTMwLWI1LWMyLTAyLTBjLWI1LTI&url=aHRiaW4vc291cmNlc190eXBlcy9ncm91cC9saW51eF91c2VyX2dyb3VwLnB5P3hpZD1ncm91cC5OYW1lJTNEYXBhY2hl&url=aHRiaW4vc291cmNlc190eXBlcy91c2VyL3VzZXJfbGludXhfaWQucHk_eGlkPXVzZXIuRG9tYWluJTNETG9jYWxIb3N0JTJDTmFtZSUzRGFwYWNoZQ&url=aHRiaW4vc291cmNlc190eXBlcy9hZGRyL3NvY2tldF9jb25uZWN0ZWRfcHJvY2Vzc2VzLnB5P3hpZD1hZGRyLklkJTNEMTkyLjE2OC4xLjg4JTNBdGVsbmV0&url=aHRiaW4vc291cmNlc190eXBlcy91c2VyL3VzZXJfcHJvY2Vzc2VzLnB5P3hpZD11c2VyLkRvbWFpbiUzRExvY2FsSG9zdCUyQ05hbWUlM0RhcGFjaGU&url=aHRiaW4vc291cmNlc190eXBlcy9DSU1fUHJvY2Vzcy9wcm9jZXNzX2N3ZC5weT94aWQ9Q0lNX1Byb2Nlc3MuSGFuZGxlJTNEMTQ3MDU&url=aHRiaW4vc291cmNlc190eXBlcy9hZGRyL3NvY2tldF9jb25uZWN0ZWRfcHJvY2Vzc2VzLnB5P3hpZD1hZGRyLklkJTNEMTkyLjE2OC4xLjg4JTNBc3No&url=aHRiaW4vc291cmNlc190eXBlcy9DSU1fUHJvY2Vzcy9wcm9jZXNzX2N3ZC5weT94aWQ9Q0lNX1Byb2Nlc3MuSGFuZGxlJTNEMTQ3MDU&url=aHRiaW4vc291cmNlc190eXBlcy9hZGRyL3NvY2tldF9jb25uZWN0ZWRfcHJvY2Vzc2VzLnB5P3hpZD1hZGRyLklkJTNEMTkyLjE2OC4xLjg4JTNBdGVsbmV0&url=aHRiaW4vc291cmNlc190eXBlcy9hZGRyL3NvY2tldF9jb25uZWN0ZWRfcHJvY2Vzc2VzLnB5P3hpZD1hZGRyLklkJTNEMTkyLjE2OC4xLjg4JTNBdGVsbmV0&url=aHRiaW4vc291cmNlc190eXBlcy9hZGRyL3NvY2tldF9jb25uZWN0ZWRfcHJvY2Vzc2VzLnB5P3hpZD1hZGRyLklkJTNEMTkyLjE2OC4xLjg4JTNBc3No&url=aHR0cDovLzE5Mi4xNjguMS44ODo4MC9TdXJ2b2wvaHRiaW4vZW50aXR5LnB5P3hpZD1DSU1fUHJvY2Vzcy5IYW5kbGU9MjA1MTI
	lib_common.MergeOutCgiRdf(theMode,cumulatedError)

if __name__ == '__main__':
	Main()

