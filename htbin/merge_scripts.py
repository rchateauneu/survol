#!/usr/bin/python

import os
import re
import sys
import time
import rdflib
import urllib
import cgi
import lib_util
import lib_common

# This CGI script is called as a CGI script by the web page inclusion.htm,
# and its parameters are input URLs.
# It merges the input urls into a single RDF document,
# then transformed into DOT, then displayed.

# Example:
# http://127.0.0.1/Survol/htbin/internals/gui_create_svg_from_several_rdfs.py?dummy=none&url=http://127.0.0.1/Survol/htbin/objtypes_wmi.py?xid=%255C%255Crchateau-HP%255Croot%255CCli%253A.&url=http://127.0.0.1/Survol/htbin/objtypes_wmi.py?xid=%255C%255Crchateau-HP%255Croot%255CDefault%253A

from rdflib import Graph

try:
	from urllib.request import urlopen
except ImportError:
	from urllib import urlopen

# Just for debugging.
logfil = open(lib_common.TmpDir() + "/gui_create_svg_from_several_rdfs.log","w")
logfil.write( "Starting logging\n" )


################################################################################

# TODO: Avoids creation of a temporary file.
def Url2Grph(grph,url,logfi = None):
	if logfi == None:
		logfi = sys.stderr
	logfi.write( "Url2Grph url=%s\n" % url )
	try:
		# Horrible hardcode, temporary.
		if sys.version_info >= (3,1,) and sys.version_info < (3,3,) :
			# ZUT !!! VOILA CE QUI ARRIVE AVEC DES REDIRECTIONS.
			#Unexpected type '<class 'bytes'>' for source 'b'<!DOCTYPE html>\n

			# OU BIEN: IMPORTER LES SCRIPTS
			# Tous les scripts ont la meme structure:
			#    grph = cgiEnv.GetGraph()
			#    ....
			#    cgiEnv.OutCgiRdf( AVEC_PARAMETRES)
			#
			# - ON FORCE LA REUTILISATION DU MEME GRAPHE.
			# - ON CACHE ENCORE PLUS rdflib.
			# - ON GARDE LES PARAMETRES SPECIFIQUES DU ROUTAGE, SURTOUT CE QUI DOIT ETRE AFFICHE EN TABLES.
			# - LA FUSION EST DEJA FAITE.
			# - ON PEUT ENVISAGER DE GARDER LES PARAMETRES DES SCRIPTS INDIVIDUELS.
			# - ON PEUT ENVISAGER DES PARAMETRES POUR LES "main"

			content = urlopen(url).read()
			result = grph.parse(content.decode('utf8'))

		elif sys.version_info >= (3,):

			# TODO: GET RID OF THIS TEMP FILE AND USE urlopen()
			tmpfilObj = lib_common.TmpFile("url2graph","rdf")
			tmpfil = tmpfilObj.Name
			logfi.write( "Url2Grph tmpfil=%s\n" % tmpfil )

			# TODO: Maybe this is an error message in HTML instead of a RDF document.
			urllib.request.urlretrieve (url, tmpfil)

			# TODO: Detect that it is not a proper RDF file.
			grph.parse(tmpfil)
		else:

			# TODO: GET RID OF THIS TEMP FILE AND USE urlopen()
			tmpfilObj = lib_common.TmpFile("url2graph","rdf")
			tmpfil = tmpfilObj.Name
			logfi.write( "Url2Grph tmpfil=%s\n" % tmpfil )

			urllib.urlretrieve (url, tmpfil)

			# TODO: Detect that it is not a proper RDF file.
			try:
				grph.parse(tmpfil)
			except Exception:
				exc = sys.exc_info()[1]
				errmsg = "Url2Grph v=" + str(sys.version_info) + " Error url=" + url + " EXC=" + str(exc)
				logfi.write("Err=[%s]\n" % (errmsg) )

				lib_common.ErrorMessageHtml( errmsg )

	# Can be: xml.sax._exceptions.SAXParseException:
	# Maybe this is a HTML file because of an error.
	# If so, display the content.
	except Exception:
		exc = sys.exc_info()[1]
		errmsg = "Url2Grph v=" + str(sys.version_info) + " Error url=" + url + " EXC=" + str(exc)
		logfi.write("Err=[%s]\n" % (errmsg) )
		lib_common.ErrorMessageHtml( errmsg )




def PrintTime():
	global logfil
	logfil.write( time.strftime('%X') + "\n" )

def ConcatOptions( url, key, value ):
	if url.find( '?' ) == -1 :
		delim = '?'
	else:
		delim = '&'
		# delim = '&amp;'
	# return url + delim + urllib.urlencode(key) + '=' + urllib.urlencode(str(value))
	return url + delim + key + '=' + str(value)

grph = Graph()

arguments = cgi.FieldStorage()

try:
	dottosvg = arguments["dottosvg"].value
except KeyError:
	dottosvg = "DotToSvgServer"
logfil.write( "dottosvg=" + dottosvg + "\n" )

# There is only one cgiEnv and "cgiEnv.OutCgiRdf()" does not generate anything.
lib_common.CgiEnvSetMergeMode()
# cgiEnv = lib_common.CgiEnv()

# Only one rdflib Graph object.
lib_util.GraphSetGlobal()

for urlfil in arguments.getlist("url"):
	# The parameters are coded in base64, although we leave the possibility not to encode them,
	# for compatibility with test scripts.
	complete_url = urlfil
	complete_url = lib_util.Base64Decode(urlfil)

	urlParsed = complete_url.Parse()

	# The CGI arguments will be injected in the cgiEnv object before calling the script.
	urlPath = urlParsed
	urlDirNam = "jjjj"
	moduNam = urlDirNam.replace("/",".")
	urlFilNam = "yyy.py"

	try:
		# argDir="sources_types.win32" urlFileNam="enumerate_top_level_windows.py"
		importedMod = lib_util.GetScriptModule(moduNam, urlFilNam)
	except Exception:
		errorMsg = sys.exc_info()[1]
		sys.stderr.write("Caught %s when loading moduNam=%s urlFilNam=%s"%(errorMsg,moduNam,urlFilNam))
		continue

	try:
		importedMod.Main()
	except Exception:
		errorMsg = sys.exc_info()[1]
		sys.stderr.write("Caught %s when executing Main in moduNam=%s urlFilNam=%s"%(errorMsg,moduNam,urlFilNam))
		continue


lib_util.GraphSetLocal()

# OutCgiRdf has been called by each script without writing anything,
# but the specific parameters per script are stored inside.
cgiEnv.OutCgiRdf()

