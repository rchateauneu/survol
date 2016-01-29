#!/usr/bin/python

import os
import re
import sys
import time
import subprocess
from subprocess import Popen, PIPE
import rdflib

import urllib

import cgi
import cgitb; cgitb.enable() # Optional; for debugging only

import lib_common

# This CGI script is called as a CGI script by the web page inclusion.htm,
# and its parameters are input URLs.
# It merges the input urls into a single RDF document,
# then transformed into DOT,
# then displayed.

# from optparse import OptionParser
from rdflib import Graph

# Just for debugging.
logfil = open(lib_common.TmpDir() + "/gui_create_svg_from_several_rdfs.log","w") 
logfil.write( "Starting logging\n" )

def PrintTime():
	global logfil
	logfil.write( time.strftime('%X') + "\n" )

def ConcatOptions( url, key, value ):
	if url.find( '?' ) == -1 :
		delim = '?'
	else:
		delim = '&'
	# return url + delim + urllib.urlencode(key) + '=' + urllib.urlencode(str(value))
	return url + delim + key + '=' + str(value)

grph = Graph()

arguments = cgi.FieldStorage()

PrintTime()

try:
	maxnodes = arguments["maxnodes"].value
except KeyError:
	maxnodes = 10000000
logfil.write( "maxnodes=" + str(maxnodes) + "\n" )

try:
	viztype = arguments["viztype"].value
except KeyError:
	# viztype = "neato"
	# circo fdp sfdp dot neato twopi
	viztype = "neato"
logfil.write( "viztype=" + viztype + "\n" )

try:
	dottosvg = arguments["dottosvg"].value
except KeyError:
	dottosvg = "DotToSvgServer"
logfil.write( "dottosvg=" + dottosvg + "\n" )

# It takes the list of urls and executes them. They must output a RDF content.
# This is slow.
# Also it could take more parameters such as a query.
# And it could be skipped if there is a single RDF to display, which is not possible yet.
cnt = 1
for urlfil in arguments.getlist("url"):
	# The idea is to avoid that the merging does not work due to the quantity of data.
	complete_url = ConcatOptions( urlfil, "maxnodes", maxnodes )
	logfil.write( "complete_url=" + complete_url + "\n" )
	logfil.write( "Merging " + urlfil + "\n" )

	lib_common.Url2Grph( grph, complete_url, logfil )
	lenGrph = len(grph)
	logfil.write( "After Merge len=" + str(lenGrph) + "\n" )
	cnt=cnt+1

# It starts at 1
if cnt == 1:
	lib_common.ErrorMessageHtml( "No input URLs" )

# There will be some new input arguments.
# If there is one RDF arg only, it will skip the merge.

PrintTime()
# The following steps should be done by us because we would like to specify our graphic parameters,
# maybe filter out some predicates, control the size of the output etc...

logfil.write( "RdfLibToDot. Conversion to dot nb statements=" + str(len(grph)) + "\n" )

# Grph2Svg( page_title, topUrl, error_msg, isSubServer, parameters, dot_style, grph, out_dest )
# Layout style est FAUX, FAUX, FAUX, FAUX.
lib_common.Grph2Svg( "Merge", "", "", False, {}, viztype, grph, lib_common.DfltOutDest() )

PrintTime()

logfil.write("Finished\n")
logfil.close()

# Another nice thing to would be to enter SPARQL queries:
# Have the result displayed immediately, as a graphic.
# Save an URL containing this query.
# It must be a separate URL, not related to merge.
# Maybe it is possible to do that with Protege?
