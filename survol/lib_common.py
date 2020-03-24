"""Common code for Survol agent"""

__author__      = "Remi Chateauneu"
__copyright__   = "Copyright 2020, Primhill Computers"
__license__     = "GPL"

import socket
import urllib
import subprocess

try:
    import simplejson as json
except ImportError:
    import json

import signal
import sys
import cgi
import os
import re
import time

import lib_kbase
import lib_util
import lib_patterns
import lib_properties
import lib_naming
import lib_properties
from lib_properties import MakeProp
import lib_exports
import lib_export_ontology
import lib_export_dot
import lib_grammar

from lib_util import NodeLiteral
from lib_util import NodeUrl
from lib_util import TimeStamp

if sys.version_info >= (3,):
    import html
    portable_escape = html.escape
else:
    portable_escape = cgi.escape


# Functions for creating uris are imported in the global namespace.
from lib_uris import *
import lib_uris

################################################################################

nodeMachine = gUriGen.HostnameUri( lib_util.currentHostname )

################################################################################

# Could be reused if we want to focus on some processes only.
# proc in [ 'bash', 'gvim', 'konsole' ]
def is_useless_process(proc):
	return False

################################################################################
	
## Also, the Apache 2.2 docs have a slightly different location for the registry key:
## HKEY_CLASSES_ROOT\.cgi\Shell\ExecCGI\Command\(Default) => C:\Perl\bin\perl.exe -wT

################################################################################

def write_dot_header( page_title, layout_style, stream, grph ):
	# Some cleanup.
	page_title_clean = page_title.strip()
	page_title_clean = page_title_clean.replace("\n", " ")
	# Title embedded in the page.
	stream.write('digraph "' + page_title_clean + '" { \n')

	# CSS style-sheet should be in the top-level directory ?
	# Not implemented in 2010: http://graphviz.org/bugs/b1874.html
	# Add a CSS-like "class" attribute
	# stream.write(' stylesheet = "rdfmon.css" \n')

	# Maybe the layout is forced.
	# dot - "hierarchical" or layered drawings of directed graphs. This is the default tool to use if edges have directionality.
	# neato - "spring model'' layouts.  This is the default tool to use if the graph is not too large (about 100 nodes) and you don't know anything else about it. Neato attempts to minimize a global energy function, which is equivalent to statistical multi-dimensional scaling.
	# fdp - "spring model'' layouts similar to those of neato, but does this by reducing forces rather than working with energy.
	# sfdp - multiscale version of fdp for the layout of large graphs.
	# twopi - radial layouts, after Graham Wills 97. Nodes are placed on concentric circles depending their distance from a given root node.
	# circo - circular layout, after Six and Tollis 99, Kauffman and Wiese 02. This is suitable for certain diagrams of multiple cyclic structures, such as certain telecommunications networks.
	# This is a style more than a dot layout.
	# sys.stderr.write("Lay=%s\n" % (layout_style) )
	if layout_style == "LAYOUT_RECT":
		dot_layout = "dot"
		# Very long lists: Or very flat tree.
		stream.write(" splines=\"ortho\"; \n")
		stream.write(" rankdir=\"LR\"; \n")
	elif layout_style == "LAYOUT_RECT_RL":
		dot_layout = "dot"
		# Very long lists: Or very flat tree.
		stream.write(" splines=\"ortho\"; \n")
		stream.write(" rankdir=\"RL\"; \n")
	elif layout_style == "LAYOUT_RECT_TB":
		dot_layout = "dot"
		# Very long lists: Or very flat tree.
		stream.write(" splines=\"ortho\"; \n")
		# stream.write(" rank=\"source\"; \n")
		stream.write(" rankdir=\"TB\"; \n")
	elif layout_style == "LAYOUT_TWOPI":
		# Used specifically for file/file_stat.py : The subdirectories
		# are vertically stacked.
		dot_layout = "twopi"
		stream.write(" rankdir=\"LR\"; \n")
	elif layout_style == "LAYOUT_SPLINE":
		# Win32_Services, many interconnections.
		dot_layout = "fdp"
		# stream.write(" splines=\"curved\"; \n") # About as fast as straight lines
		stream.write(" splines=\"spline\"; \n") # Slower than "curved" but acceptable.
		stream.write(" rankdir=\"LR\"; \n")
		# stream.write(" splines=\"compound\"; \n") ### TRES LENT
	else:
		dot_layout = "fdp" # Faster than "dot"
		# TODO: Maybe we could use the number of elements len(grph)  ?
		stream.write(" rankdir=\"LR\"; \n")
	stream.write(" layout=\"" + dot_layout + "\"; \n")

	# TODO: Take the font from the CSS html_exports.css
	# Example on Windows: stream.write(" node [ fontname=\"DejaVu Sans\" ] ; \n")
	stream.write(" node [ %s ] ; \n" % lib_exports.FontString() )
	return dot_layout

################################################################################

# Copies a file to standard output.
# TODO: On Linux, consider splice.
# See lib_kbase.triplestore_to_stream_xml for a similar situation.
def copy_to_output_destination(logfil, svg_out_filnam, out_dest):
	logfil.write( TimeStamp() + " Output without conversion: %s\n" % svg_out_filnam  )
	infil = open(svg_out_filnam,'rb')
	strInRead = infil.read()
	try:
		nbOut = out_dest.write(strInRead)
	except TypeError as exc:
		# This happens when:
		# Python 2 and wsgiref.simple_server: unicode argument expected, got 'str'
		# Python 3 and wsgiref.simple_server: string argument expected, got 'bytes'
		nbOut = out_dest.write(strInRead.decode('latin1'))

	logfil.write( TimeStamp() + " End of output without conversion: %s chars\n" % str(nbOut) )
	infil.close()

################################################################################

# TODO: Consider using the Python module pygraphviz: Small speedup probably.
# But the priority is to avoid graphes which are too long to route.
# TODO: Consider using the Python module pydot,
# but anyway it needs to have graphviz already installed.
# Also, creating an intermediary files helps debugging.
def _dot_to_svg(dot_filnam_after, logfil, viztype, out_dest):
	DEBUG("viztype=%s",viztype)
	tmpSvgFil = TmpFile("_dot_to_svg","svg")
	svg_out_filnam = tmpSvgFil.Name
	# dot -Kneato

	# Dot/Graphviz no longer changes PATH at installation. It must be done BEFORE.
	dot_path = "dot"

	if lib_util.isPlatformLinux:
		# TODO: This is arbitrary because old Graphviz version.
		# TODO: Take the fonts from html_exports.css
		# dotFonts = ["-Gfontpath=/usr/share/fonts/TTF", "-Gfontnames=svg", "-Nfontname=VeraBd.ttf","-Efontname=VeraBd.ttf"]
		dotFonts = [
                    # "-Gfontpath=/usr/share/fonts/dejavu", 
                    "-Gfontpath=/usr/share/fonts", 
                    "-Gfontnames=svg",
                    "-Nfontname=DejaVuSans.ttf",
                    "-Efontname=DejaVuSans.ttf"]
	else:
		dotFonts = []

	# Old versions of dot need the layout on the command line.
	# This is maybe a bit faster than os.open because no shell and direct write to the output.
	svg_command = [ dot_path,"-K",viztype,"-Tsvg",dot_filnam_after,"-o",svg_out_filnam, \
		"-v","-Goverlap=false" ] + dotFonts
	msg = "svg_command=" + " ".join(svg_command)
	DEBUG(msg)
	logfil.write(TimeStamp()+" "+msg+"\n")

	ret = subprocess.call( svg_command, stdout=logfil, stderr=logfil, shell=False )
	logfil.write(TimeStamp()+" Process ret=%d\n" % ret)

	if not os.path.isfile( svg_out_filnam ):
		ErrorMessageHtml("SVG file " + svg_out_filnam + " could not be created." )
	
	# If there is an error, we should write it as an HTML page.
	# On the other hand it will be impossible to pipe the output
	# because it would assume a SVG document.
	# TODO: See that later.

	# https://stackoverflow.com/questions/5667576/can-i-set-the-html-title-of-a-pdf-file-served-by-my-apache-web-server
	dictHttpProperties = [ ( "Content-Disposition", 'inline; filename="Survol_Download"') ]

	logfil.write( TimeStamp() + " Writing SVG header\n" )
	lib_util.WrtHeader( "image/svg+xml", dictHttpProperties )

	# Here, we are sure that the output file is closed.
	copy_to_output_destination(logfil,svg_out_filnam,out_dest)

################################################################################

# This transforms a RDF triplestore into a temporary DOT file, which is
# transformed by GraphViz into a SVG file sent to the HTTP browser.
def _graph_to_svg(page_title, error_msg, isSubServer, parameters, grph, parameterized_links, topUrl, dot_style):
	tmpLogFil = TmpFile("_graph_to_svg","log")
	try:
		logfil = open(tmpLogFil.Name,"w")
	except:
		exc = sys.exc_info()[1]
		ERROR("_graph_to_svg caught %s when opening:%s",str(exc),tmpLogFil.Name)
		ErrorMessageHtml("_graph_to_svg caught %s when opening:%s\n"%(str(exc),tmpLogFil.Name))

	logfil.write( "Starting logging\n" )

	tmpDotFil = TmpFile("Grph2Dot","dot")
	dot_filnam_after = tmpDotFil.Name
	rdfoutfil = open( dot_filnam_after, "w" )
	logfil.write( TimeStamp()+" Created "+dot_filnam_after+"\n" )

	dot_layout = write_dot_header( page_title, dot_style['layout_style'], rdfoutfil, grph )
	lib_exports.WriteDotLegend( page_title, topUrl, error_msg, isSubServer, parameters, parameterized_links, rdfoutfil, grph )
	logfil.write( TimeStamp()+" Legend written\n" )
	lib_export_dot.Rdf2Dot( grph, logfil, rdfoutfil, dot_style['collapsed_properties'] )
	logfil.write( TimeStamp()+" About to close dot file\n" )

	# BEWARE: Do this because the file is about to be reopened from another process.
	rdfoutfil.flush()
	os.fsync( rdfoutfil.fileno() )
	rdfoutfil.close()

	out_dest = lib_util.get_default_output_destination()

	_dot_to_svg(dot_filnam_after, logfil, dot_layout, out_dest)
	logfil.write( TimeStamp()+" closing log file\n" )
	logfil.close()

################################################################################

# The result can be sent to the Web browser in several formats.
# TODO: The nodes should be displayed always in the same order.
# THIS IS NOT THE CASE IN HTML AND SVG !!
def OutCgiMode( theCgi, topUrl, mode, errorMsg = None, isSubServer=False ):
	theCgi.BindIdenticalNodes()

	grph = theCgi.m_graph
	pageTitle = theCgi.m_page_title
	dotLayout = theCgi.m_layoutParams
	parameters = theCgi.m_parameters
	parameterized_links = theCgi.m_parameterized_links

	if mode == "html":
		# Used rarely and performance not very important. This returns a HTML page.
		import lib_export_html
		lib_export_html.Grph2Html( theCgi, topUrl, errorMsg, isSubServer, globalCgiEnvList)
	elif mode == "json":
		lib_exports.Grph2Json( pageTitle, errorMsg, isSubServer, parameters, grph)
	elif mode == "menu":
		lib_exports.Grph2Menu( pageTitle, errorMsg, isSubServer, parameters, grph)
	elif mode == "rdf":
		lib_export_ontology.Grph2Rdf(grph)
	elif mode in ["svg",""]:
		# Default mode, because graphviz did not like several CGI arguments in a SVG document (Bug ?).
		_graph_to_svg(pageTitle, errorMsg, isSubServer, parameters, grph, parameterized_links, topUrl, dotLayout)
	else:
		ERROR("OutCgiMode invalid mode=%s",mode)
		ErrorMessageHtml("OutCgiMode invalid mode=%s"%mode)

	# TODO: Add a special mode where the triplestore grph is simply returned, without serialization.
	# TODO: This is much faster when in the client library because no marshalling is needed.
	# TODO: Implementation: Store grph in a global variable. This can work with one client only.
	# TODO: Maybe a thread-specific variable.
	# TODO: The caller must destroy the grph triplestore after using it.

	# TODO: Other modes stored in a configuration file:
	# These mode define a reporting mechanism to send the triplestore
	# to an external repository:
	# - Graph database such as Neo4J
	# - Log file.
	# The client, when reporting, must make a specific call to this script.
	# An acknowledgment and status HTML message is sent back to the caller.



################################################################################

def make_dot_layout(dot_layout, collapsed_properties ):
	return { 'layout_style': dot_layout, 'collapsed_properties':collapsed_properties }

################################################################################

def _get_calling_module_doc():
	"""
		Works if called from Apache, cgiserver.py or wsgiserver.py
		This is a global and can be fetched differently, if needed.
		It returns the whole content.
	"""

	#sys.stderr.write("_get_calling_module_doc Main module:%s\n"% str(sys.modules['__main__']))


	# If it uses an unique CGI script.
	if globalMergeMode or lib_util.is_wsgi_server():
		try:
			# This is a bit of a hack.
			import inspect
			frame=inspect.currentframe()
			frame=frame.f_back.f_back
			code=frame.f_code
			filnamCaller = code.co_filename
			filnamCaller = filnamCaller.replace("\\",".").replace("/",".")
			filnamCaller = filnamCaller[:-3] # Strings ".py" at the end.
			modulePrefix = "survol."
			htbinIdx = filnamCaller.find(modulePrefix)
			filnamCaller = filnamCaller[htbinIdx + len(modulePrefix):]

			try:
				# Another try if "survol." is duplicated, possibly for Win10 and Py3.8:
				if filnamCaller.startswith(modulePrefix):
					filnamCaller = filnamCaller[len(modulePrefix):]
				moduleCaller = sys.modules[filnamCaller]
			except:
				return filnamCaller + ":No doc"

			theDoc = moduleCaller.__doc__
			if theDoc:
				theDoc = theDoc.strip()
			else:
				theDoc = ""
			#sys.stderr.write("_get_calling_module_doc  moduleCaller.__doc__=%s\n" % theDoc)
			return theDoc
		except:
			exc = sys.exc_info()[1]
			WARNING("_get_calling_module_doc Caught when getting doc:%s",str(exc))
			return "Caught when getting doc:"+str(exc)
	else:
		try:
			# This does not work when in WSGI mode, nor when merging.
			mainModu = sys.modules['__main__']
			#sys.stderr.write("_get_calling_module_doc Main module:%s\n"% mainModu.__name__ )
			page_title = mainModu.__doc__
			if page_title:
				page_title = page_title.strip()
				return page_title
			else:
				return "No __main__ doc"
		except:
			exc = sys.exc_info()[1]
			return "_get_calling_module_doc (Caught %s)" % str(exc)


################################################################################

globalMergeMode = False
globalCgiEnvList = []
globalGraph = None

# There is only one cgiEnv and "cgiEnv.OutCgiRdf()" does not generate anything.
# It is related to WSGI in the extent that global variables should not harm things.
def CgiEnvMergeMode():
	global globalMergeMode
	global globalCgiEnvList
	global globalGraph

	globalMergeMode = True
	globalCgiEnvList = []
	globalGraph = lib_kbase.MakeGraph()

# OutCgiRdf has been called by each script without writing anything,
# but the specific parameters per script are stored inside.
def MergeOutCgiRdf(theMode,cumulatedError):
	global globalMergeMode
	global globalCgiEnvList
	global globalGraph

	page_title = "Merge of %d scripts:\n" % len(globalCgiEnvList)
	delim_title = ""
	# This is equivalent to: make_dot_layout( "", [] )
	layoutParams = { 'layout_style': "", 'collapsed_properties':[] }
	cgiParams = {}
	cgiParamLinks = {}
	for theCgiEnv in globalCgiEnvList:
		# theCgiEnv.m_page_title contains just the first line.
		# (page_title_first,page_title_rest) = lib_util.SplitTextTitleRest(theCgiEnv.m_page_title)
		(page_title_first,page_title_rest) = (theCgiEnv.m_page_title,theCgiEnv.m_page_subtitle)
		page_title += delim_title + page_title_first
		if page_title_rest:
			page_title += " (" + page_title_rest + ")"
		delim_title = ", "

		layoutParams['layout_style'] = theCgiEnv.m_layoutParams['layout_style']
		layoutParams['collapsed_properties'].extend( theCgiEnv.m_layoutParams['collapsed_properties'] )

		# The dictionaries of parameters and corresponding links are merged.
		try:
			cgiParams.update(theCgiEnv.m_parameters)
			cgiParamLinks.update(theCgiEnv.m_parameterized_links)
		except ValueError:
			errorMsg = sys.exc_info()[1]
			WARNING("Error:%s Parameters:%s",errorMsg,str(theCgiEnv.m_parameters))

	# Eliminate duplicates in the list of collapsed properties.
	myList = layoutParams['collapsed_properties']
	mySet = set(myList)
	layoutParams['collapsed_properties'] = list(mySet)

	topUrl = lib_util.TopUrl( "", "" )

	pseudoCgi = CgiEnv()
	pseudoCgi.m_graph = globalGraph
	pseudoCgi.m_page_title = page_title
	pseudoCgi.m_page_subtitle = ""
	pseudoCgi.m_layoutParams = layoutParams
	# Not sure this is the best value, but this is usually done.
	# TODO: We should have a plain map for all m_arguments occurences.
	pseudoCgi.m_arguments = cgi.FieldStorage()
	pseudoCgi.m_parameters = cgiParams
	pseudoCgi.m_parameterized_links = cgiParamLinks
	pseudoCgi.m_entity_type = ""
	pseudoCgi.m_entity_id = ""
	pseudoCgi.m_entity_host = ""

	# A single rendering of all RDF nodes and links merged from several scripts.
	OutCgiMode( pseudoCgi, topUrl, theMode, errorMsg = cumulatedError )

	return

################################################################################

class CgiEnv():
	"""
		This class parses the CGI environment variables which define an entity.
	"""
	def __init__(self, parameters = {}, can_process_remote = False ):
		# TODO: This value is read again in OutCgiRdf, we could save time by making this object global.
		#sys.stderr.write( "CgiEnv parameters=%s\n" % ( str(parameters) ) )

		# TODO: When running from cgiserver.py, and if QUERY_STRING is finished by a dot ".", this dot
		# TODO: is removed. Workaround: Any CGI variable added after.
		# TODO: Also: Several slashes "/" are merged into one.
		# TODO: Example: "xid=http://192.168.1.83:5988/." becomes "xid=http:/192.168.1.83:5988/"
		# TODO: ... or "xx.py?xid=smbshr.Id=////WDMyCloudMirror///rchateau" become "xx.py?xid=smbshr.Id=/WDMyCloudMirror/rchateau"
		# TODO: Replace by "xid=http:%2F%2F192.168.1.83:5988/."
		# Maybe a bad collapsing of URL ?
		# sys.stderr.write("QUERY_STRING=%s\n" % os.environ['QUERY_STRING'] )
		mode = lib_util.GuessDisplayMode()

		# Contains the optional arguments, needed by calling scripts.
		self.m_parameters = parameters

		self.m_parameterized_links = dict()


		# When in merge mode, the display parameters must be stored in a place accessible by the graph.

		docModuAll = _get_calling_module_doc()

		# Take only the first non-empty line. See lib_util.FromModuleToDoc()
		self.m_page_title, self.m_page_subtitle = lib_util.SplitTextTitleRest(docModuAll)

		# Title page contains __doc__ plus object label.
		callingUrl = lib_util.RequestUri()
		self.m_calling_url = callingUrl
		DEBUG("CgiEnv m_page_title=%s m_calling_url=%s",self.m_page_title,self.m_calling_url)
		#sys.stderr.write("CgiEnv lib_util.globalOutMach:%s\n" %(lib_util.globalOutMach.__class__.__name__))
		parsedEntityUri = lib_naming.ParseEntityUri(callingUrl,longDisplay=False,force_entity_ip_addr=None)
		if parsedEntityUri[2]:
			# If there is an object to display.
			# Practically, we are in the script "entity.py" and the single doc string is "Overview"
			fullTitle = parsedEntityUri[0]
			self.m_page_title += " " + fullTitle

			# We assume there is an object, and therefore a class and its description.
			entity_class = parsedEntityUri[1]

			# Similar code in objtypes.py
			# TODO: Maybe replace this by _get_calling_module_doc.
			entity_module = lib_util.GetEntityModule(entity_class)
			entDoc = entity_module.__doc__
			# The convention is the first line treated as a title.
			if entDoc:
				entDoc = entDoc.strip()
				self.m_page_title += "\n" + entDoc

		# Global CanProcessRemote has precedence over parameter can_process_remote
		# which should probably be deprecated, although they do not have exactly the same role:
		# * Global CanProcessRemote is used by entity.py to display scripts which have this capability.
		# * Parameter can_process_remote is used to inform, at execution time, of this capability.
		# Many scripts are not enumerated by entity.py so a global CanProcessRemote is not necessary.
		# For clarity, it might be fine to replace the parameter can_process_remote by the global value.
		# There cannot be nasty consequences except that some scripts might not be displayed
		# when they should be, and vice-versa.
		try:
			globalCanProcessRemote = globals()["CanProcessRemote"]
		except KeyError:
			globalCanProcessRemote = False

		if can_process_remote != globalCanProcessRemote:
			# sys.stderr.write("INCONSISTENCY CanProcessRemote\n") # ... which is not an issue.
			can_process_remote = True

		self.m_can_process_remote = can_process_remote

		self.m_arguments = cgi.FieldStorage()

		(self.m_entity_type,self.m_entity_id,self.m_entity_host) = self.GetXid()
		#sys.stderr.write("CgiEnv m_entity_type=%s m_entity_id=%s m_entity_host=%s\n"%(self.m_entity_type,self.m_entity_id,self.m_entity_host))
		self.m_entity_id_dict = lib_util.SplitMoniker(self.m_entity_id)

		# Depending on the caller module, maybe the arguments should be 64decoded. See "sql/query".
		# As the entity type is available, it is possible to import it and check if it encodes it arguments.
		# See presence of source_types.sql.query.DecodeCgiArg(keyWord,cgiArg) for example.

		# This is probably too generous to indicate a local host.
		self.test_remote_if_possible(can_process_remote)

		# TODO: HOW WILL WE RESTORE THE ORIGINAL DISPLAY MODE ?
		if mode == "edit":
			self.enter_edition_mode()

	def test_remote_if_possible(self,can_process_remote):
		# This is probably too generous to indicate a local host.
		if can_process_remote or self.m_entity_host is None:
			return

		if lib_util.IsLocalAddress(self.m_entity_host):
			return

		ErrorMessageHtml("Script %s cannot handle remote hosts on host=%s" % ( sys.argv[0], self.m_entity_host ) )

	def GetGraph(self):
		global globalMergeMode
		if globalMergeMode:
			# When in merge mode, the same object must be always returned.
			self.m_graph = globalGraph
		else:
			self.m_graph = lib_kbase.MakeGraph()
		return self.m_graph

	# We avoid several CGI arguments because Dot/Graphviz wants no ampersand "&" in the URLs.
	# This might change because I suspect bugs in old versions of Graphviz.
	def GetXid(self):
		try:
			# See variable xidCgiDelimiter.
			# TODO: Consider base64 encoding all arguments with "Xid=".
			# The benefit would be to have the same encoding for all arguments.
			xid = self.m_arguments["xid"].value
		except KeyError:
			# See function enter_edition_mode
			try:
				return ( "", "", "" )
				# TODO: Not finished, useless or debugging purpose ?
				entity_type = self.m_arguments["edimodtype"].value
				monikDelim = ""
				entity_id = ""
				for ediKey in self.m_arguments:
					if ediKey[:11] == "edimodargs_":
						monikKey = ediKey[11:]
						monikVal = self.m_arguments[ediKey].value
						entity_id += monikDelim + monikKey + "=" + monikVal
						monikDelim = "&"

				return ( entity_type, entity_id, "" )
			except KeyError:
				# No host, for the moment.
				return ( "", "", "" )
		return lib_util.ParseXid( xid )
	
	# TODO: If no arguments, allow to edit it.
	# TODO: Same font as in SVG mode.
	# Suggest all available scritps for this entity type.
	# Add legend in RDF mode:
	# http://stackoverflow.com/questions/3499056/making-a-legend-key-in-graphviz
	def enter_edition_mode(self):
		"""This allow to edit the CGI parameters when in SVG (Graphviz) mode"""
		import lib_export_html
		import lib_edition_parameters

		formAction = os.environ['SCRIPT_NAME']
		DEBUG("enter_edition_mode formAction=%s",formAction)

		lib_util.WrtHeader('text/html')

		# It uses the same CSS as in HTML mode.
		lib_export_html.DisplayHtmlTextHeader(self.m_page_title+" - parameters")

		print("<body>")

		print("<h3>%s</h3><br>"%self.m_page_title)

		htmlForm = "".join( lib_edition_parameters.FormEditionParameters(formAction,self) )
		print(htmlForm)

		print("</body>")
		print("</html>")
		sys.exit(0)

	# These are the parameters specific to the script, which are edit in our HTML form, in enter_edition_mode().
	# They must have a default value. Maybe we could always have an edition mode when their value
	# is not set.
	# If the parameter is "cimom", it will extract the host of Uris like these: Wee GetHost()
	# https://jdd:test@acme.com:5959/cimv2:CIM_RegisteredProfile.InstanceID="acme:1"

	def get_parameters(self,paramkey):
		#sys.stderr.write("get_parameters paramkey='%s' m_arguments=%s\n" % (paramkey,str(self.m_arguments) ) )

		# Default value if no CGI argument.
		try:
			dfltValue = self.m_parameters[paramkey]
			# sys.stderr.write("get_parameters %s Default=%s\n" % ( paramkey, dfltValue ) )
			hasDfltVal = True
		except KeyError:
			hasDfltVal = False

		# unchecked_hidden
		hasArgValue = True
		try:
			# If the script parameter is passed as a CGI argument.
			# BEWARE !!! An empty argument triggers an exception !!!
			# Same problem if the same argument appears several times: This will be a list.
			paramVal = self.m_arguments[paramkey].value
			#sys.stderr.write("get_parameters paramkey='%s' paramVal='%s' as CGI\n" % ( paramkey, paramVal ) )
		except KeyError:
			DEBUG("get_parameters paramkey='%s' not as CGI", paramkey )
			hasArgValue = False

		# Now converts it to the type of the default value. Otherwise untouched.
		if hasDfltVal:
			if hasArgValue:
				paramTyp = type(dfltValue)
				paramVal = paramTyp( paramVal )
				#sys.stderr.write("get_parameters paramkey='%s' paramVal='%s' after conversion to %s\n" % ( paramkey, paramVal, str(paramTyp) ) )
			else:
				# If the parameters were edited but the value did not appear,
				# it can only be a Boolean with a clear check box.
				# https://stackoverflow.com/questions/1809494/post-the-checkboxes-that-are-unchecked
				# Unchecked check boxes are not POSTed.
				try:
					self.m_arguments["edimodtype"]
					paramVal = False

					# Sets the right value of the parameter because HTML form do not POST unchecked check boxes.
					# Therefore, if in edit mode, a parameter is not returned, it can only be a False boolean.
					self.m_parameters[paramkey] = paramVal
					DEBUG("get_parameters paramkey='%s' set to FALSE", paramkey )
				except KeyError:
					paramVal = dfltValue
					DEBUG("get_parameters paramkey='%s' set to paramVal='%s'", paramkey, paramVal )
		else:
			if not hasArgValue:
				#sys.stderr.write("get_parameters no value nor default for paramkey='%s' m_parameters=%s\n" % ( paramkey, str(self.m_parameters)))
				# lib_util.InfoMessageHtml("get_parameters no value nor default for %s\n" % paramkey )
				paramVal = ""
			else:
				DEBUG("get_parameters nothing for paramkey='%s'", ( paramkey ))

		# TODO: Beware, empty strings are NOT send by the HTML form,
		# TODO: so an empty string must be equal to the default value.

		return paramVal

	# This is used for compatibility with the legacy scripts, which has a single id.
	# Now all parameters must have a key. As a transition, GetId() will return the value of
	# the value of an unique key-value pair.
	# If this class is not in DMTF, we might need some sort of data dictionary.
	def GetId(self):
		DEBUG("GetId m_entity_type=%s m_entity_id=%s", self.m_entity_type, str( self.m_entity_id ) )
		try:
			# If this is a top-level url, no object type, therefore no id.
			if self.m_entity_type == "":
				return ""

			splitKV = lib_util.SplitMoniker(self.m_entity_id)
			DEBUG("GetId splitKV=%s", str( splitKV ) )

			# If this class is defined in our ontology, then we know the first property.
			entOnto = lib_util.OntologyClassKeys(self.m_entity_type)
			if entOnto:
				keyFirst = entOnto[0]
				# Only if this mandatory key is in the dict.
				try:
					return splitKV[keyFirst]
				except KeyError:
					# This is a desperate case...
					pass
			# Returns the first value but this is not reliable at all.
			for key in splitKV:
				return splitKV[key]
		except KeyError:
			pass

		# If no parameters although one was requested.
		self.enter_edition_mode()
		return ""

	# TODO: Ca va etre de facon generale le moyen d'acces aux donnees et donc inclure le cimom
	# soit par example cimom=http://192.168.1.83:5988  ou bien seulement un nom de machine.
	# C'est ce que WMI va utiliser. On peut imaginer aussi de mettre un serveur ftp ?
	# Ou bien un serveur SNMP ?
	# C est plus un serveur qu un host. Le host est une propriete de l'objet, pas une clef d'acces.
	# C est ce qui va permettre d acceder au meme fichier par un disque partage et par ftp.
	def GetHost(self):
		return self.m_entity_host

	# TODO: Would probably be faster by searching for the last "/".
	# '\\\\RCHATEAU-HP\\root\\cimv2:Win32_Process.Handle="0"'  => "root\\cimv2:Win32_Process"
	# https://jdd:test@acme.com:5959/cimv2:Win32_SoftwareFeature.Name="Havana",ProductName="Havana",Version="1.0"  => ""
	def get_namespace_type(self):
		return lib_util.parse_namespace_type(self.m_entity_type)

	# When in merge mode, these parameters must be aggregated, and used only during
	# the unique generation of graphic data.
	# TODO: "OutCgiRdf" should be changed to a more appropriate name, such as "DisplayTripleStore"
	def OutCgiRdf(self, dot_layout = "", collapsed_properties=[] ):
		global globalCgiEnvList
		#sys.stderr.write("OutCgiRdf lib_util.globalOutMach:%s\n" %(lib_util.globalOutMach.__class__.__name__))
		DEBUG("OutCgiRdf globalMergeMode=%d m_calling_url=%s m_page_title=%s",globalMergeMode,self.m_calling_url, self.m_page_title.replace("\n","<NL>") )

		self.m_layoutParams = make_dot_layout( dot_layout, collapsed_properties )

		mode = lib_util.GuessDisplayMode()

		topUrl = lib_util.TopUrl( self.m_entity_type, self.m_entity_id )

		if self.m_page_title is None:
			self.m_page_title = "PAGE TITLE SHOULD BE SET"
			self.m_page_subtitle = "PAGE SUBTITLE SHOULD BE SET"

		# See if this can be used in lib_client.py and merge_scritps.py.
		if globalMergeMode:
			# At the end, only one call to OutCgiMode() will be made.
			globalCgiEnvList.append(self)
		else:
			OutCgiMode( self, topUrl, mode )

	# Example: cgiEnv.add_parameterized_links( "Next", { paramkeyStartIndex : startIndex + maxInstances } )
	def add_parameterized_links(self, urlLabel, paramsMap):
		"""This adds the parameters of an URL which points to the same page,
		but with different CGI parameters. This URLS will displays basically
		the same things, from the same script."""

		# We want to display links associated to the parameters.
		# The use case is "Prev/Next" when paging between many values.
		# This calculates the URLS and returns a map of { "label":"urls" }

		# Copy the existing parameters of the script. This will be updated.
		prmsCopy = dict()
		for argK in cgi.FieldStorage():
			argV = cgi.FieldStorage()[argK].value
			# sys.stderr.write("add_parameterized_links argK=%s argV=%s\n"%(argK,argV))
			prmsCopy[argK] = lib_util.urllib_quote(argV)

		# Update these parameters with the values specific for this label.
		for paramKey in paramsMap:
			# Check that it is a valid parameter.
			try:
				self.m_parameters[paramKey]
			except KeyError:
				ErrorMessageHtml("Parameter %s should be defined for a link"%paramKey)
			prmsCopy[paramKey] = paramsMap[paramKey]

		DEBUG("prmsCopy=%s",str(prmsCopy))

		# Now create an URL with these updated params.
		idxCgi = self.m_calling_url.find("?")
		if idxCgi < 0:
			labelledUrl = self.m_calling_url
		else:
			labelledUrl = self.m_calling_url[:idxCgi]

		# ENCODING PROBLEM HERE.
		# ENCODING PROBLEM HERE.
		# ENCODING PROBLEM HERE.
		# OK http://127.0.0.1/Survol/survol/class_wbem.py?Start+index=0&Max+instances=800&xid=http%3A%2F%2Fprimhillcomputers.ddns.net%3A5988%2Froot%2Fcimv2%3APG_UnixProcess.&edimodtype=root%2Fcimv2%3APG_UnixProcess
		# OK http://rchateau-hp:8000/survol/class_wbem.py?xid=http%3A%2F%2F192.168.0.17%3A5988%2Froot%2Fcimv2%3APG_UnixProcess.
		# KO http://rchateau-hp:8000/survol/class_wbem.py?xid=http%3A//192.168.0.17%3A5988/root/cimv2%3APG_UnixProcess.
		# Conversion to str() because of integer parameters.
		kvPairsConcat = "&amp;amp;".join( "%s=%s" % ( paramKey,str(prmsCopy[paramKey]).replace("/","%2F")) for paramKey in prmsCopy )
		labelledUrl += "?" + kvPairsConcat

		DEBUG("labelledUrl=%s",labelledUrl)

		self.m_parameterized_links[urlLabel] = labelledUrl

	# Graphs might contain the same entities calculated by different servers.
	# This can happen here, when several URLs are merged.
	# This can happen also in the JavaScript client, where several URLs
	# are dragged and dropped in the same browser session.
	# The same object will have different URLs depending on the server where it is detected.
	# For example, a remote database might be seen from different machines.
	# These different nodes, representing the same object, must be associated.
	# For this, we calculated for each node, its universal alias.
	# This is done, basically, by taking the URL, replacing the host name of where
	# the object sits, by an IP address.
	# Nodes with the same
	def BindIdenticalNodes(self):

		# This maps each universal alias to the set of nodes which have it.
		# At the end, all nodes with the same universal alias are
		# linked with a special property.
		dictUniToObjs = dict()

		def HasUnivAlias(anObject):
			if lib_kbase.IsLiteral(anObject):
				return False

			if ( anObject.find("entity.py") >= 0 ) or ( anObject.find("entity_wbem.py") >= 0 ) or( anObject.find("entity_wmi.py") >= 0 ):
				return True

			return False

		# This calculates the universal alias for each node representing an object.
		def PrepareBinding(anObject):

			if not HasUnivAlias(anObject):
				return

			uniDescr = lib_exports.NodeToUniversalAlias(anObject)
			try:
				dictUniToObjs[uniDescr].add(anObject)
			except KeyError:
				dictUniToObjs[uniDescr] = { anObject }

		for aSubj, aPred, anObj in self.m_graph:
			PrepareBinding(aSubj)
			PrepareBinding(anObj)

		for anUniDescr in dictUniToObjs:
			relatedNodes = dictUniToObjs[anUniDescr]
			if len(relatedNodes) < 2:
				continue

			nodePrevious = None

			# These specific links must be very visible and short.
			# They should be displayed identically in SVG and D3.
			# Ideally, all objects with the same alias should be a single graphic shape,
			# with all scripts of each object.
			for otherNode in relatedNodes:
				if nodePrevious:
					self.m_graph.add((nodePrevious,lib_properties.pc.property_alias,otherNode))
				nodePrevious = otherNode


################################################################################

globalErrorMessageEnabled = True

# Used when merging several scripts, otherwise there is no way to find
# which scripts produced an error.
def enable_error_message(flag):
	global globalErrorMessageEnabled
	globalErrorMessageEnabled = flag

def ErrorMessageHtml(message):
	if globalErrorMessageEnabled:
		ERROR("ErrorMessageHtml %s. Exiting.",message)
		# If we are in Json mode, this returns a special json document with the error message.
		try:
			qry = os.environ["QUERY_STRING"]
			isJson = qry.endswith("mode=json")
			if isJson:
				lib_exports.WriteJsonError(message)
				sys.exit(0)
			
		except KeyError:
			pass

		# 'SERVER_SOFTWARE': 'SimpleHTTP/0.6 Python/2.7.10', 'WSGIServer/0.2'
		try:
			server_software = os.environ['SERVER_SOFTWARE']
		except KeyError:
			server_software = "Unknown_SERVER_SOFTWARE"
		lib_util.InfoMessageHtml(message)
		DEBUG("ErrorMessageHtml about to leave. server_software=%s" % server_software)

		if server_software.find('WSGIServer') >= 0:
			# WSGI server is persistent and should not exit.
			raise RuntimeError("Server software=" + server_software)
		else:
			sys.exit(0)
	else:
		# Instead of exiting, it throws an exception which can be used by merge_scripts.py
		DEBUG("ErrorMessageHtml DISABLED")
		# It might be displayed in a HTML document.
		messageClean = portable_escape(message)
		raise Exception("ErrorMessageHtml raised:%s\n"%messageClean)

################################################################################

def SubProcPOpen(command):
	try:
		retPipe = subprocess.Popen(command, bufsize=100000, shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	except OSError:
		ErrorMessageHtml("Cannot run "+" ".join(command))

	# For the win32/script windows_network_devices.py,
	# we need shell=True, because it runs the command "wmic",
	# but this might be a security hole.
	return retPipe

def SubProcCall(command):
	# For doxygen, we should have shell=True but this is NOT safe.
        # Shell is however needed for unit tests.
	DEBUG("command=%s",command)
	ret = subprocess.call(command, stdout=sys.stderr, stderr=sys.stderr, shell=True)
	return ret

################################################################################

def __check_if_directory(dir):
	if( os.path.isdir(dir) ):
		return dir
	raise Exception("Not a dir:"+dir)

# The temp directory as specified by the operating system.
def get_temporary_directory():

	# TODO: For some reason, the user "apache" used by httpd cannot write,
	# on some Linux distributions, to the directory "/tmp"
	# https://blog.lysender.com/2015/07/centos-7-selinux-php-apache-cannot-writeaccess-file-no-matter-what/
	# This is a temporary fix. Maybe related to SELinux.
	try:
		if lib_util.isPlatformLinux:
			# 'SERVER_SOFTWARE': 'Apache/2.4.29 (Fedora)'
			if os.environ["SERVER_SOFTWARE"].startswith("Apache/"):
				# 'HTTP_HOST': 'vps516494.ovh.net'
				if os.environ["HTTP_HOST"].startswith("vps516494."):
					return "/home/rchateau/tmp_apache"
	except:
		pass

	try:
		# Maybe these environment variables are undefined for Apache user.
		return __check_if_directory(os.environ["TEMP"].replace('\\', '/'))
	except Exception:
		pass

	try:
		return __check_if_directory(os.environ["TMP"].replace('\\', '/'))
	except Exception:
		pass

	if lib_util.isPlatformWindows:
		try:
			return __check_if_directory(os.environ["USERPROFILE"].replace('\\', '/') + "/AppData/Local/Temp")
		except Exception:
			pass

		try:
			return __check_if_directory("C:/Windows/Temp")
		except Exception:
			pass

		return __check_if_directory("C:/Temp")
	else:
		return __check_if_directory("/tmp")

# This will not change during a process.
tmpDir = get_temporary_directory()
		
# Creates and automatically delete, a file and possibly a dir.
# TODO: Consider using the module tempfile.
class TmpFile:
	def __init__(self,prefix="tmp", suffix="tmp",subdir=None):
		procPid = os.getpid()
		currDir = tmpDir

		if subdir:
			customDir = "/%s.%d" % ( subdir, procPid )
			currDir += customDir
			if not os.path.isdir(currDir):
				os.mkdir(currDir)
			else:
				# TODO: Cleanup ??
				pass
			self.TmpDirToDel = currDir
		else:
			self.TmpDirToDel = None

		if prefix is None or suffix is None:
			self.Name = None
			return

		self.Name = "%s/%s.%d.%s" % ( currDir, prefix, procPid, suffix )
		DEBUG("tmp=%s", self.Name )

	def DbgDelFil(self,filNam):
		if True:
			DEBUG("Deleting=%s",filNam)
			os.remove(filNam)
		else:
			WARNING("NOT Deleting=%s",filNam)

	def __del__(self):
		try:
			if self.Name:
				self.DbgDelFil(self.Name)

			# Extra check, not to remove everything.
			if self.TmpDirToDel not in [None,"/",""]:
				DEBUG("About to del %s", self.TmpDirToDel )
				for root, dirs, files in os.walk(self.TmpDirToDel, topdown=False):
					for name in files:
						self.DbgDelFil(os.path.join(root, name))
					for name in dirs:
						os.rmdir(os.path.join(root, name))
						pass

		except Exception:
			exc = sys.exc_info()[1]
			ERROR("__del__.Caught: %s. TmpDirToDel=%s Name=%s", str(exc), str(self.TmpDirToDel), str(self.Name) )
		return


################################################################################

# This is deprecated and was used to reduce the number fo displayed filed,
# by hiding the ones which are not really interesting.
def _is_shared_library(path):

	if lib_util.isPlatformWindows:
		tmp, fileExt = os.path.splitext(path)
		return fileExt.upper() in [ ".DLL" ]

	if lib_util.isPlatformLinux:
		# We could also check if this is really a shared library.
		# file /lib/libm-2.7.so: ELF 32-bit LSB shared object etc...
		if path.endswith(".so"):
			return True

		# Not sure about "M" and "I". Also: Should precompile regexes.
		for rgx in [ r'/lib/.*\.so\..*', r'/usr/lib/.*\.so\..*' ] :
			if re.match( rgx, path, re.M|re.I):
				return True

		for start in [ '/usr/share/locale/', '/usr/share/fonts/', '/etc/locale/', '/var/cache/fontconfig/', '/usr/lib/jvm/' ] :
			if path.startswith( start ):
				return True

	return False

# A file containing fonts and other stuff not usefull to understand how a process works.
# So by default they are ot displayed. This should be deprecated.
def _is_fonts_file(path):

	if lib_util.isPlatformWindows:
		tmp, fileExt = os.path.splitext(path)
		# sys.stderr.write("_is_fonts_file fileExt=%s\n" % fileExt)
		return fileExt in [ ".ttf", ".ttc" ]

	elif lib_util.isPlatformLinux:
		for start in [ '/usr/share/locale/', '/usr/share/fonts/', '/etc/locale/', '/var/cache/fontconfig/', '/usr/lib/jvm/' ] :
			if path.startswith( start ):
				return True

	return False

# Used when displaying all files open by a process: There are many of them,
# so the irrelevant files are hidden. This should be an option.
def is_meaningless_file(path, removeSharedLibs, removeFontsFile):
	if removeSharedLibs:
		if _is_shared_library(path):
			return True

	if removeFontsFile:
		if _is_fonts_file(path):
			# sys.stderr.write("YES is_meaningless_file path=%s\n" % path)
			return True

	return False


################################################################################
# Reformat the username because in psutil.users() it is "Remi",
# but from process.username(), it is "PCVERO\Remi"
#
# http://msdn.microsoft.com/en-gb/library/windows/desktop/aa380525(v=vs.85).aspx
# User principal name (UPN) format is used to specify an Internet-style name,
# such as UserName@Example.Microsoft.com.
#
# The down-level logon name format is used to specify a domain
# and a user account in that domain, for example, DOMAIN\UserName.
# The following table summarizes the parts of a down-level logon name.
#
# Some say that: UserName@DOMAIN also works.
# 
# http://serverfault.com/questions/371150/any-difference-between-domain-username-and-usernamedomain-local
def format_username(usrnam):
	# BEWARE: WE ARE LOSING THE DOMAIN NAME.
	shortnam = usrnam.split('\\')[-1]

	# return shortnam + "@" + lib_util.currentHostname
	return shortnam

################################################################################
# How to display RDF files ?
#
# <?xml version="1.0" encoding="iso-8859-1"?>
# <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
# <html> 
#
# And the XSL file might contain something like:
# <?xml version="1.0" encoding="iso-8859-1"?>
# <actu xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="schema.xsd">
# <?xml-stylesheet type="text/xsl" href="fichier.xsl"?>
# <article rubrique="fiscal" dateArticle="03/11/09" idArticle="art3200">
# <copyright>..... 

# Avec la geolocalisation des adresses IP, on pourrait fabriquer des fichers KML.

################################################################################

