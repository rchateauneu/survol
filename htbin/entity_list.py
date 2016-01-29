#!/usr/bin/python

# It receives as CGI arguments, the entity type and its id. Some examples:
# Type      Id
# --------------
# Process   Pid. Plus machine?
# File      Path
# Dll       Path
# Function  Function name. Plus the file name such as in "/usr/lib/libbz2.so:BZ2_bzCompress" ?
#           Mais on voudrait que la fonction puisse etre indeterminee. Donc le fichier serait une propriete
#           sans pour autant faire partie de l'id.
# Socket    Adresse IP + port.
# Samba     Adresse IP + nom du partage.

import os
import re
import urllib

import cgi

import rdflib
import lib_common
import lib_util

cgiEnv = lib_common.CgiEnv()
entity_type = cgiEnv.m_entity_type
entity_id = cgiEnv.m_entity_id

# TODO: if the cgi argument mode == "rdf",
# this creates a RDF document instead of HTML.


# OU BIEN: ON VA RENVOYER DU RDF, et OutCgiRdf va s'occuper 
# du transcodage.
# MAIS: ON VEUT GARDER LA POSSIBILITE D'AVOIR DE CHOUETTES
# PAGES EN HTML.
# ALORS ON VA CREER entity.py qui va jouer le role
# de entity_list.py, et va aussi ajouter une propriete rdf.
# (Mais en fait ce devrait etre une propriete "html_source"),
# on s'en fiche, on n'exploite pas ca.
# Et comme cette page n'utilise pas OutCgiRdf, elle fabriquera
# du HTML, en fait n'importe quel type MIME.



# v=PATH_TRANSLATED => /home/rchateau/Developpement/ReverseEngineeringApps/PythonStyle
try:
	cgiPathTranslated = os.environ["SCRIPT_FILENAME"]
except KeyError:
	lib_common.ErrorMessageHtml("Cannot read PATH_TRANSLATED" )

# Directory=/home/rchateau/Developpement/ReverseEngineeringApps/PythonStyle Type=process Id=5256 
relative_dir = lib_common.SourceDir(entity_type)
directory = lib_util.gblTopScripts + relative_dir
script_name = os.environ["SCRIPT_NAME"]
script_dirname = os.path.dirname( script_name )

print ("Content-Type: text/html")
print ("")
print ("<html>")
print ("<head>")
print ("<title>URLs for entity " + entity_type + " id=" + entity_id + "</title>")
print ("</head>")
print ("<body>")
print ("<br>Cwd=" + os.getcwd() )
print ("<br>Directory=" + directory)
print ("<br>Type=" + entity_type)
print ("<br>Id=" + entity_id)
print ("<br>UriRoot=" + lib_util.uriRoot)
print ("<br>cgiPathTranslated=" + cgiPathTranslated)
print ("<br>SCRIPT_NAME=" + script_name)
print ("<br>script_dirname=" + script_dirname)
print ("<br>")

print ('<a href="' + lib_util.EntityUri(entity_type,entity_id) + '">Same information, in RDF</a><br>')

# v=SCRIPT_NAME => /htbin/entity_list.py
# http://127.0.0.1:8642/htbin//home/rchateau/Developpement/ReverseEngineeringApps/PythonStyle/htbin/sources/BY_so/cgi_linux_nm.py?fullid=so_%2Fusr%2Flib%2Flibgmcop.so

print( "<table border=1>" )

# Temporary files created by Unix editors.
rgx_tilda = re.compile(".*~$")
rgx_swapf = re.compile(".*\.swp$")

# On peut proposer un menu.
# On mettra le lien qui permet d'appeler le CGI avec le bon id.
for path, dirs, files in os.walk(directory):
	# Concatenate the type and the id so the cgi could receive different sorts of parameters.
	encodedEntityId=lib_util.EncodeUri(entity_id)

	for fil in files:
		if rgx_tilda.match( fil ):
			continue
		if rgx_swapf.match( fil ):
			continue

		url_rdf = rdflib.term.URIRef( uriRoot + relative_dir + "/" + fil + "?" + lib_util.EncodeEntityId(entity_type,encodedEntityId) )

		print( "<tr>" )

		print( "<td>" )
		print( fil )
		print( "</td>" )

		print( "<td>" )
		print( "<a href='" + url_rdf + "'>RDF</a>" )
		print( "</td>" )

		url_html = "internals/rdf2html.py?url=" + lib_util.EncodeUri(url_rdf)
		print( "<td>" )
		print( "<a href='" + url_html + "'>HTML</a>" )
		print( "</td>" )

		url_merge_remote = lib_common.Url2Svg( url_rdf )
		print( "<td>" )
		print( "<a href='" + url_merge_remote + "'>SVG remote url</a>" )
		print( "</td>" )

		infoDict = lib_common.DeserializeScriptInfo(url_rdf)
		print( "<td>" )
		print( infoDict["info"] )
		print( "</td>" )


		print( "</tr>" )

print( "</table>" )

print( "<br>End<br>")

print( "</body></html>" )

