#!/usr/bin/python

from BaseHTTPServer import BaseHTTPRequestHandler,HTTPServer
import CGIHTTPServer
import re
import os
from os import curdir, sep
import cgi
import time
import urllib
import quik
from quik import FileLoader

def PrintTime():
	print time.strftime('%X')


PORT_NUMBER = 1234

# Specialised htpp server which pares its input html file and replaces
# templates by SLP values.

class SlpService:
	def __init__( self, name, url, rest, label ):
		print "Name="+ name + " url=" + url
		self.m_name = name
		self.m_url = url
		self.m_rest = rest
		self.m_label = label

# Only the services we want.
def GetSlpServices(filter):
	services_list = []
	stream = os.popen("slptool findsrvs service:" + filter)
	# service:ftp.smallbox://192.168.100.1:21,65535
	lbl = 0
	for line in stream:
		print "Li=" + line
		matchObj = re.match( r'service:([^:]*):/?/?([^,]*)(.*)', line, re.M|re.I)
		if matchObj:
			service = SlpService(
					matchObj.group(1) ,
					'http' + '://' + matchObj.group(2) ,
					matchObj.group(3) ,
					'label_' + str(lbl) )
			services_list.append( service )
		else:
			print "No match!!"
		lbl = lbl + 1
	return services_list

def ProcessSlpTmpl(tmplfile):
	service_filter='http.rdf'
	services_list = GetSlpServices(service_filter)

	# loader = FileLoader('html')
	loader = FileLoader('.')
	template = loader.load_template(tmplfile)
	generated_html = template.render(
		{
			'filter': service_filter,
			'services': services_list
		},
		loader=loader).encode('utf-8')

	outfile = tmplfile + ".htm"
	fil = open(outfile,'w')
	fil.write(generated_html)
	fil.close()
	return outfile

def ProcessPython(tmplfile):
	selected_services = split("kjhglkjhl")

	outfile = tmplfile + ".htm"
	fil = open(outfile,'w')
	fil.write(generated_html)
	fil.close()
	return outfile

# fullfile contains something like "svc_merge_rdf_files.py"
# The processing could be explicitely done here.
def CallMerge(fullfile,cgivars,rdf_out_filnam):
	rdf_out_filnam = "merge_result.rdf"
	# os.remove(rdf_out_filnam)
	cgivars_decoded=urllib.unquote(cgivars).decode('utf8')
	list_urls = cgivars_decoded.split(';')

	separ=' '
	argurls=separ.join( list_urls )
	command = fullfile + " " + argurls + " -v --output=" + rdf_out_filnam
        print "CallMerge=" + command
	PrintTime()
	rdf_stream = os.popen(command)
	PrintTime()
	print "CallMerge output:"
	for rdf_line in rdf_stream:
		print rdf_line
	print "\n"

def ReplaceEdgesLabels(inFileName,outFileName):
	print "ReplaceEdgesLabels " + inFileName + " " + outFileName
	inFil = open(inFileName)
	outFil = open(outFileName,'w')

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

	inFil.close()
	outFil.close()


# Generate a svg file:
# rdfdot -png -svg result.rdf out.svg
def CallToRdf(rdf_out_filnam,svg_out_filnam):
	# TODO: Must wait until the file is finished !!!!!!!!!!!!!!

	print "CallToRdf " + rdf_out_filnam + " " + svg_out_filnam
	# dot_command = "rdfdot -png -svg " + rdf_out_filnam + " " + svg_out_filnam
	dot_filnam_before = rdf_out_filnam + ".before.dot"
	# os.remove(dot_filnam_before)
	dot_filnam_before_err = rdf_out_filnam + ".before.dot.err"
	# os.remove(dot_filnam_before_err)
	dot_command = "rdfdot " + rdf_out_filnam + " > " + dot_filnam_before + " 2> " + dot_filnam_before_err
        print "ToDot=" + dot_command
	PrintTime()
	dot_stream = os.popen(dot_command)
	print "Dot command output:"
	for dot_line in dot_stream:
		print dot_line
	print "\n"
	PrintTime()

	dot_filnam_after = rdf_out_filnam + ".dot"
	# os.remove(dot_filnam_after)
	ReplaceEdgesLabels( dot_filnam_before, dot_filnam_after )

	# dot -Kneato -Tsvg merge_result.rdf.dot -o merge_result.svg -Gfontpath=/usr/share/fonts/TTF -Gfontnames=svg -Nfontname=VeraBd.ttf -Efontname=VeraBd.ttf
	# dot -Kneato -Tsvg merge_result.rdf.dot -o merge_result.svg -Gfontpath=/usr/share/fonts/TTF -Gfontnames=svg -Nfontname=VeraBd.ttf -Efontname=VeraBd.ttf  -v  -Goverlap=false 

	PrintTime()
	svg_command = "dot -Kneato -Tsvg " + dot_filnam_after + " -o " + svg_out_filnam \
		+ " -Gfontpath=/usr/share/fonts/TTF -Gfontnames=svg" \
		+ " -Nfontname=VeraBd.ttf -Efontname=VeraBd.ttf" \
		+ " -v  -Goverlap=false "
	PrintTime()

	# http://www.graphviz.org/doc/info/attrs.html#d:fontname
	# Several possible options.
	# svg_command = "dot -Kfdp -o " + svg_out_filnam + " -Tsvg  " + dot_filnam
	# svg_command = "dot -Kneato -o " + svg_out_filnam + " -Tsvg  " + dot_filnam
	# command = "rdfdot -png -svg " + rdf_out_filnam + " " + svg_out_filnam
        print "ToSvg=" + svg_command
	# os.remove(svg_out_filnam)
	svg_stream = os.popen(svg_command)
	print "Svg command output:"
	for svg_line in svg_stream:
		print svg_line
	print "\n"
	PrintTime()


class myReqHandler(BaseHTTPRequestHandler):
	
	#Handler for the GET requests
	def do_GET(self):
		if self.path=="/":
			self.path="/list_rdf_generators.htm"
		fullfile= curdir + sep + self.path

		cgivars = ""
		print "fullfile=" + fullfile
		idx_quest = fullfile.find('?')
		print "idx_quest=" + str(idx_quest)
		if idx_quest != -1:
			cgivars = fullfile[idx_quest + 1:]
			fullfile = fullfile[0:idx_quest]

		print "fullfile=" + fullfile
		print "cgivars=" + cgivars

		if fullfile.endswith(".tmpl.htm"):
			print "Template replacement"
			fullfile = ProcessSlpTmpl( fullfile )

		if fullfile.endswith(".htm"):
                	print "Get path=" + fullfile
			mimetype = 'html'
			infil = open(fullfile) 
			self.send_response(200)
			self.send_header('Content-type',mimetype)
			self.end_headers()
			self.wfile.write(infil.read())
			infil.close()
			return

		if fullfile.endswith(".py"):
			# TODO: FILE MUST BE A PARAMETER !!!!!!!!!!!!!!!!!!
			# For the moment it is OK.
			rdf_out_filnam = "merge_result.rdf"
			if fullfile.endswith("svc_merge_rdf_files.py"):
				CallMerge(fullfile, cgivars, rdf_out_filnam)
				mimetype = 'rdf+xml'
				infil = open(rdf_out_filnam) 
			elif fullfile.endswith("svc_rdf_to_svg.py"):
				svg_out_filnam = "from_rdf.svg"
				CallToRdf(rdf_out_filnam,svg_out_filnam)
				# image/svg+xml ??
				print "Streaming " + svg_out_filnam
				mimetype = 'svg+xml'
				infil = open(svg_out_filnam) 
			else:
				print "Should not happen:" + fullfile


			self.send_response(200)
			self.send_header('Content-type',mimetype)
			self.end_headers()
			self.wfile.write(infil.read())
			infil.close()


			# ICI: Envoyer le transformation du RDF en SVG sur une autre frame.


			# Apres ca, le resultat peut etre expose avec SLP,
			# surtout si on le recalcule de facon periodique.
			return

		print "Should process the CGI variables"

	#Handler for the POST requests
	def do_POST(self):
                print "Post path=" + self.path

		form = cgi.FieldStorage(
			fp=self.rfile, 
			headers=self.headers,
			environ={'REQUEST_METHOD':'POST',
	                 'CONTENT_TYPE':self.headers['Content-Type'],
		})

                #for theKey in form:
                #    print "Key=%s " % ( theKey )
                #    print "Key=%s is: %s" % ( theKey, form[theKey].name )
                #    print "Key=%s is: %s" % ( theKey, form[theKey].value )
		self.send_response(200)
		self.end_headers()
		self.wfile.write("Result\r\n")
		for theKey in form:
			self.wfile.write( "Key=%s is: %s\r\n" % ( theKey, form[theKey].value ) )
			#self.wfile.write( "Key=%s is: %s\r\n" % ( theKey, str(form[theKey]) ) )
			#self.wfile.write( "Key=%s \r\n" % ( theKey ) )
			return			
			
try:
	# Create a web server and define the handler to manage the incoming request
	httpServer = HTTPServer(('', PORT_NUMBER), myReqHandler)
	print 'Started httpserver on port ' , PORT_NUMBER

	# handler.cgi_directories = [""]


	# Wait forever for incoming http requests
	httpServer.serve_forever()

except KeyboardInterrupt:
	print '^C received, shutting down the web server'
	httpServer.socket.close()
