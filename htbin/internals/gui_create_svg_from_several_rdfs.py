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

# Transforms the dot file before processing by graphviz. This is necessary
# to add some data that rdfdot cannot do.
def ReplaceEdgesLabels(inFileName,outFileName):
	global logfil
	logfil.write( "ReplaceEdgesLabels " + inFileName + " " + outFileName + "\n" )
	inFil = open(inFileName)
	outFil = open(outFileName,'w')

	nblin=0
	for inLine in inFil:
		# For edges
		# node19 -> node12 [url="http://primhillcomputers.com/ontologies/memmap" label="memmap"];
   		tmpLine = re.sub(    \
			r'(.*) -> ([^ ]*) \[label="<([^"]*)/([^>]*)>"];',    \
			r'\1 -> \2 [URL="\3/\4", label="\4", fontsize="3" ];',    \
			inLine)
		#	r'\1 -> \2 [labelURL="\3/\4" label="\4" fontsize="3" ];',    \

		# node2 [label="<urn://DuoLnx/proc/12840>", shape=box, fontcolor=blue, style=rounded];
    		outLine = re.sub(    \
			r'(.*) \[label="<([^"]*)/([^>]*)>",',    \
			r'\1 [URL="\2/\3", label="\3",',    \
			tmpLine)
		#	r'\1 [labelURL="\2/\3" label="\3" fontsize="3",',    \

		outFil.write(outLine)
		nblin = nblin+1

	inFil.close()
	outFil.close()
	logfil.write( "ReplaceEdgesLabels nblin=" + str(nblin) + "\n" )

grph = Graph()

arguments = cgi.FieldStorage()

PrintTime()
cnt = 1

try:
	maxnodes = arguments["maxnodes"].value
except KeyError:
	maxnodes = 10000000
logfil.write( "maxnodes=" + str(maxnodes) + "\n" )

try:
	viztype = arguments["viztype"].value
except KeyError:
	viztype = "neato"
logfil.write( "viztype=" + viztype + "\n" )

try:
	rdfmerger = arguments["rdfmerger"].value
except KeyError:
	rdfmerger = "PythonRdfMerge"
logfil.write( "rdfmerger=" + rdfmerger + "\n" )

try:
	rdftodot = arguments["rdftodot"].value
except KeyError:
	rdftodot = "PerlRdfToDot"
logfil.write( "rdftodot=" + rdftodot + "\n" )

try:
	dottosvg = arguments["dottosvg"].value
except KeyError:
	dottosvg = "DotToSvgServer"
logfil.write( "dottosvg=" + dottosvg + "\n" )

rdf_out_filnam= lib_common.TmpDir() + "/" + "outfil.rdf"
if rdfmerger == "PythonRdfMerge":
	# It takes the list of urls and executes them. They must output a RDF content.
	# This is slow.
	# Also it could take more parameters such as a query.
	# And it could be skipped if there is a single RDF to display, which is not possible yet.
	for urlfil in arguments.getlist("url"):
		tmpfil = lib_common.TmpDir() + "/tmp_" + str(cnt) + ".tmp"
		logfil.write( "urlfil=" + urlfil + "\n" )
		# We add some generic options. Not used yet.
		# The idea is to avoid that the merging does not work due to the quantity of data.
		complete_url = ConcatOptions( urlfil, "maxnodes", maxnodes )
		logfil.write( "complete_url=" + complete_url + "\n" )
		logfil.write( "Merging " + urlfil + " into " + tmpfil + "\n" )

		urllib.urlretrieve (complete_url, tmpfil)
		grph.parse(tmpfil)
		cnt=cnt+1

	# It starts at 1
	if cnt == 1:
		lib_common.ErrorMessageHtml( "No input URLs" )

	outRdfFil = open(rdf_out_filnam, 'w')
	outRdfFil.write( grph.serialize(format="xml") )
	outRdfFil.close()
elif rdfmerger == "JenaRdfMerge":
	lib_common.ErrorMessageHtml( "Not done yet rdfmerger=" + rdfmerger )
else:
	lib_common.ErrorMessageHtml( "Cannot execute rdfmerger=" + rdfmerger )

# Transformation of a RDF document into a DOT document.
# This next step can also be done with JenaTools,
# so it must be parameterized.
# Also, it could be a separate script which would return a dot document.
# Also, some specific parameters could be added.
# The only sad thing is that of we do the merge of the RDFs inputs
# with Jena, and also the generation of DOT, this could be done 
# in a single step. Therefore it is worth doing the schedule of these steps
# in this specific script: So we are going to extract the various steps and
# make the communicate.
# There will be some new input arguments.
# If there is one RDF arg only, it will skip the merge.

PrintTime()
# The following steps should be done by us because we would like to specify our graphic parameters,
# maybe filter out some predicates, control the size of the output etc...
dot_filnam_before = rdf_out_filnam + ".before.dot"
dot_filnam_before_err = rdf_out_filnam + ".before.dot.err"
dot_filnam_after = rdf_out_filnam + ".dot"
# os.remove(dot_filnam_after)

if rdftodot == "PerlRdfToDot":
	# This is slow.
	logfil.write("PATH=" + os.environ['PATH'])
	# This specifies the path for Apache which does not point to /usr/local/bin
	dot_command = "/usr/local/bin/rdfdot " + rdf_out_filnam + " > " + dot_filnam_before + " 2> " + dot_filnam_before_err

	logfil.write( "ToDot=" + dot_command + "\n" )
	PrintTime()
	# We must be sure that the command is finished before using its output file.
	dot_stream = os.popen(dot_command)
	logfil.write( "rdfdot output:" )
	for dot_line in dot_stream:
		logfil.write( dot_line )
	logfil.write( "\n" )
	PrintTime()

	err_stream = open(dot_filnam_before_err)
	logfil.write( "rdfdot error:" )
	for err_line in err_stream:
		logfil.write( err_line )
	logfil.write( "\n" )

	# This is a cleanup of the output dot document.
	# Is it necessary in all cases ?
	# Anyway it is part of the previous step.
	ReplaceEdgesLabels( dot_filnam_before, dot_filnam_after )
elif rdftodot == "JenaToolsRdfToDot":
	jena_command = "/home/rchateau/ApacheJena/JenaToDot/RunJenaToDot.sh " + rdf_out_filnam
	logfil.write( "JenaToDot=" + jena_command + "\n" )

	outfil = open(dot_filnam_after, "w")

	# The default value for "shell" is not true, apparently.
	proc = Popen( jena_command, shell=True, stdout=outfil, stderr=PIPE )
	return_code = proc.wait()
	outfil.close()
	str_err = proc.stderr.read()
	logfil.write("ret="+str(return_code))
	logfil.write("err="+str_err)
	if return_code != 0:
		print "Failure %s:\n%s" % (return_code, proc.stderr.read())
		lib_common.ErrorMessageHtml(
			"ret=" + return_code + "\n" +
			"err=" + str_err + "\n"
		)
else:
	lib_common.ErrorMessageHtml( "Cannot execute rdftodot=" + rdftodot + "\n" )

# dot -Kneato -Tsvg merge_result.rdf.dot -o merge_result.svg -Gfontpath=/usr/share/fonts/TTF -Gfontnames=svg -Nfontname=VeraBd.ttf -Efontname=VeraBd.ttf
# dot -Kneato -Tsvg merge_result.rdf.dot -o merge_result.svg -Gfontpath=/usr/share/fonts/TTF -Gfontnames=svg -Nfontname=VeraBd.ttf -Efontname=VeraBd.ttf  -v  -Goverlap=false 

# Last bit which calls graphviz. Again, this can be parameterized,
# because we could as well return a HTML document integrating the dot
# result plus a call to webgraphiz in Javascript.

PrintTime()

if dottosvg == "DotToSvgServer":
	svg_out_filnam= lib_common.TmpDir() + "/tmp_final.svg"
	# dot -Kneato
	svg_command = "dot -K" + viztype + " -Tsvg " + dot_filnam_after + " -o " + svg_out_filnam \
		+ " -Gfontpath=/usr/share/fonts/TTF -Gfontnames=svg" \
		+ " -Nfontname=VeraBd.ttf -Efontname=VeraBd.ttf" \
	+ " -v  -Goverlap=false 2>&1"
	logfil.write("svg_command=" + svg_command + "\n")

	# http://www.graphviz.org/doc/info/attrs.html#d:fontname
	# Several possible options.
	# svg_command = "dot -Kfdp -o " + svg_out_filnam + " -Tsvg  " + dot_filnam
	# svg_command = "dot -Kneato -o " + svg_out_filnam + " -Tsvg  " + dot_filnam
	# command = "rdfdot -png -svg " + rdf_out_filnam + " " + svg_out_filnam
	# os.remove(svg_out_filnam)
	svg_stream = os.popen(svg_command)
	logfil.write( "Dot command output:" )
	for svg_line in svg_stream:
		logfil.write( svg_line )
	logfil.write( "\n" )
	PrintTime()

	print "Content-Type: image/svg+xml"
	print ""

	# Here, we are sure that the output file is closed.
	infil = open(svg_out_filnam) 
	print infil.read()
elif dottosvg == "DotToSvgClient":
	# http://www.webgraphviz.com/
	lib_common.ErrorMessageHtml("Cannot execute Webgraphviz not done yet")
else:
	lib_common.ErrorMessageHtml( "Cannot execute dottosvg=" + dottosvg)



logfil.write("Finished\n")
PrintTime()
logfil.close()

# Another nice thing to would be to enter SPARQL queries:
# Have the result displayed immediately, as a graphic.
# Save an URL containing this query.
# It must be a separate URL, not related to merge.
# Maybe it is possible to do that with Protege?
