import lib_properties
import lib_naming
import lib_util
import rdflib
from lib_properties import pc
import sys
import time
import cgi
import re
import json
import six

# "http://primhillcomputers.com/ontologies/smbshare" = > "smbshare"
def AntiPredicateUri(uri):
	return uri[ len(lib_properties.primns_slash) : ]

################################################################################

# Current URL but in edition mode.
# PROBLEM: SI PAS DE ENTITY_ID A EDITER CAR "TOP" ALORS ON REBOUCLE SUR Edit:
# DONC DETECTER LE TYPE DE L'ENTITE EN FOCNTION DU DIRECTORY ET AUCUN SI "TOP".
def ModedUrl(otherMode):
	script = lib_util.RequestUri()

	mtch_url = re.match("(.*[\?\&]mode=)([a-zA-Z0-9]*)(.*)", script)
	if mtch_url:
		edtUrl = mtch_url.group(1) + otherMode + mtch_url.group(3)
	else:
		edtUrl = ConcatenateCgi( script, "mode=" + otherMode )
	return edtUrl

################################################################################
def TruncateInSpace(labText,maxLenLab):
	if len( labText ) > maxLenLab:
		idx = labText.find(" ",maxLenLab)
		# sys.stderr.write("idx=%d\n"%idx)
		if idx < 0:
			idx = maxLenLab

			# BEWARE: This must not fall in the middle of an html entity "&amp;", etc... ...
			idxSemiColon = labText.find(";",idx)
			# sys.stderr.write("idxSemiColon=%d\n"%idxSemiColon)
			if idxSemiColon < 0:
				idx = maxLenLab
			else:
				idx = idxSemiColon + 1 # Just after the semi-colon.

		# sys.stderr.write("labText=%s idx=%d\n"%(labText,idx))
		return labText[:idx]
	else:
		return labText

################################################################################

maxHtmlTitleLenPerCol = 40
withBrDelim = '<BR ALIGN="LEFT" />'

# Inserts "<BR/>" in a HTML string so it is wrapped in a HTML label.
def StrWithBr(str, colspan = 1):
	lenStr = len(str)
	maxHtmlTitleLen = colspan * maxHtmlTitleLenPerCol
	if lenStr < maxHtmlTitleLen:
		return str

	splt = str.split(" ")
	totLen = 0
	resu = ""
	currLine = ""
	for currStr in splt:
		subLen = len(currStr)
		if totLen + subLen < maxHtmlTitleLen:
			currLine += " " + currStr
			totLen += subLen
			continue
		if resu:
			resu += withBrDelim
		resu += currLine
		currLine = currStr
		totLen = subLen

	if currLine:
		if resu != "":
			resu += withBrDelim
		resu += currLine
	return resu

################################################################################

# Adds a key value pair at the end of the url with the right delimiter.
# TODO: Checks that the argument is not already there.
# TODO: Most of times, it is used for changing the mode.
def ConcatenateCgi(url,keyvalpair):
	if url.rfind( '?' ) == -1:
		return url + "?" + keyvalpair
	else:
		return url + "&" + keyvalpair

################################################################################

# TODO: Set the right criteria for an old Graphviz version.
new_graphiz = True # sys.version_info >= (3,)

# TODO: This is temporary because only old graphviz versions dot not implement that.
def DotBold(str):
	return "<b>%s</b>" % str if new_graphiz else str

def DotUL(str):
	return "<u>%s</u>" % str if new_graphiz else str

def DotIt(str):
	return "<i>%s</i>" % str if new_graphiz else str

################################################################################

from lib_util import WrtAsUtf
from lib_util import WrtHeader

################################################################################

# Transforms a RDF graph into a HTML page.
def Grph2Html( page_title, error_msg, isSubServer, parameters, grph):
	# TODO: Est-ce necessaire d'utiliser WrtAsUtf au lieu de print() ?
	# Peut-etre oui, a cause des sockets?
	WrtHeader('text/html')
	# WrtAsUtf( "Content-type: text/html\n\n<head>" )
	WrtAsUtf( "<head>" )

	# TODO: Encode the HTML special characters.
	WrtAsUtf( "<title>" + page_title + "</title>")

	# TODO: Essayer de rassembler les literaux relatifs au memes noeuds, pour faire une belle presentation.

	WrtAsUtf( ' </head> <body>')

	WrtAsUtf('<table border="1">')

	WrtAsUtf('<tr><td colspan="3"><a href="' + ModedUrl("edit") + '">CGI parameters edition</a></td></tr>')

	for keyParam,valParam in parameters.items():
		WrtAsUtf('<tr><td>' + keyParam + '</td><td colspan="2">' + valParam + '</td></tr>')

	WrtAsUtf('<tr><td colspan="3"><a href="' + ModedUrl("svg") + '">Content as SVG</a></td></tr>')
	WrtAsUtf('<tr><td colspan="3"><a href="' + ModedUrl("rdf") + '">Content as RDF</a></td></tr>')
	WrtAsUtf('<tr><td colspan="3">' + str(len(grph)) + ' nodes</td></tr>')

	if error_msg != None:
		WrtAsUtf('<tr><td colspan="3"><b>' + error_msg + '</b></td></tr>')

	if isSubServer:
		WrtAsUtf('<tr><td colspan="3"><a href="' + ModedUrl("stop") + '">Stop subserver</a></td></tr>')

	by_subj = dict()
	for subj, pred, obj in grph:
		# No point displaying some keys if there is no value.
		if pred in [ pc.property_image, pc.property_information ] :
			if str(obj) == "":
				continue

		the_tup = ( pred, obj )
		try:
			by_subj[ subj ].append( the_tup )
		except KeyError:
			by_subj[ subj ] = [ the_tup ]

	for subj, the_tup_list in list( by_subj.items() ):

		subj_str = str(subj)
		subj_title = lib_naming.ParseEntityUri(subj_str)[0]

		cnt_rows = len( the_tup_list )

		mustWriteColOne = True

		for pred, obj in the_tup_list:
			WrtAsUtf( "<tr>" )

			if mustWriteColOne:
				WrtAsUtf( '<td rowspan="' + str(cnt_rows) + '"><a href="' + subj_str + '">'+ subj_title +"</a></td>")
				mustWriteColOne = False

			obj_str = str(obj)

			if isinstance( obj , (rdflib.URIRef, rdflib.BNode)):
				obj_title = lib_naming.ParseEntityUri(obj_str)[0]
				WrtAsUtf( "<td>" + AntiPredicateUri(str(pred)) + "</td>")
				url_with_mode = ConcatenateCgi( obj_str, "mode=html" )
				WrtAsUtf( '<td><a href="' + url_with_mode + '">' + obj_title + "</a></td>")
			else:
				if pred == pc.property_information :
					WrtAsUtf( '<td colspan="2">' + obj_str + "</td>")
				else:
					WrtAsUtf( '<td>' + AntiPredicateUri(str(pred)) + "</td>")
					WrtAsUtf( '<td>' + obj_str + "</td>")

			WrtAsUtf( "</tr>")

	WrtAsUtf( " </table> </body> </html> ")

################################################################################
# Transforms a RDF graph into a JSON document. From Edouard.

def Grph2Json(page_title, error_msg, isSubServer, parameters, grph):
	WrtHeader('application/json')

	links = []
	nodes = []
	graph = {}

	by_subj = dict()
	for subj, pred, obj in grph:
		the_tup = (pred, obj)
		try:
			by_subj[subj].append(the_tup)
		except KeyError:
			by_subj[subj] = [the_tup]

	for subj, the_tup_list in list(by_subj.items()):
		subj_str = str(subj)
		subj_title = lib_naming.ParseEntityUri(subj_str)[0]
		nodes.extend([{'id': subj_title}])
		mustWriteColOne = True

		for pred, obj in the_tup_list:
			if mustWriteColOne:
				mustWriteColOne = False
				obj_str = str(obj)
			if isinstance(obj, (rdflib.URIRef, rdflib.BNode)):
				obj_title = lib_naming.ParseEntityUri(obj_str)[0]
				links.extend([{'source': subj_title, 'target': obj_title}])

	graph["nodes"] = nodes
	graph["links"] = links
	print(json.dumps(graph, indent=2))


################################################################################

# Used by all CGI scripts when they have finished adding triples to the current RDF graph.
# This just writes a RDF document which can be used as-is by browser,
# or by another scripts which will process this RDF as input, for example when merging RDF data.
# Consider adding reformatting when the output is a browser ... if this can be detected !!
# It is probably possible with the CGI environment variable HTTP_USER_AGENT.
# Also, the display preference could be stored with the Python library cookielib.
#
# AUSSI: On pourrait, sous certaines conditions, transformer la sortie en HTML ou en SVG
# (Et/ou envoyer du Javascript avec des appels rdfquery pour affichage dans le navigateur)
# Ca pourrait dependre d'une variable CGI: mode=RDF/HTML etc...
# Ici: On peut prendre la valeur de "mode" en dissequant l'URL du Referer.
#
def Grph2Rdf(grph):
	WrtHeader('text/rdf')

	# Format support can be extended with plugins,
	# but 'xml', 'n3', 'nt', 'trix', 'rdfa' are built in.
	out_dest = lib_util.DfltOutDest()
	grph.serialize( destination = out_dest, format="xml")


# This is very primitive and maybe should be replaced by a standard function,
# but lib_util.EncodeUri() replaces "too much", and SVG urls cannot encode an ampersand...
# The problems comes from "&mode=edit" or "&mode=html" etc...
# TODO: If we can fix this, then "xid" can be replaced by "entity_type/entity_id"
def UrlToSvg(url):
	if lib_util.isPlatformWindows:
		# If one ampersand only, "error on line 28 at column 75: EntityRef: expecting ';'"
		# when displaying the SVG file.
		# Windows, Python 3.2, Graphviz 2.36
		return url.replace( "&", "&amp;amp;" )
	else:
		if sys.version_info <= (2,5):
			# Linux, Python 2.5.  Tested on Mandriva.
			# Maybe we should do the same as the others.
			return url.replace( "&", "&amp;" )
		else:
			# Tested with Python 2.7 on Fedora.
			return url.replace( "&", "&amp;amp;" )

def WriteDotLegend( page_title, topUrl, errMsg, isSubServer, parameters, stream, grph ):

	# This allows to enter directly the URL parameters, so we can access directly an object.
	# This will allow to choose the entity type, and each parameter of the URL (Taken
	# from the ontology). It also edits the parameters of the current URL.
	def UrlDirectAccess():
		return "direct_access.py"

	# This adds links which can display the same content in a different output format.
	def LegendAddAlternateDisplayLinks(stream):
		# So we can change parameters of this CGI script.
		urlHtml = ModedUrl("html")
		urlJson = ModedUrl("json")
		urlRdf = ModedUrl("rdf")

		urlHtmlReplaced = UrlToSvg( urlHtml )
		urlJsonReplaced = UrlToSvg( urlJson )
		urlRdfReplaced = UrlToSvg( urlRdf )

		# BEWARE: Port numbers syntax ":8080/" is forbidden in URIs: Strange bug !
		# SO THESE LINKS DO NOT WORK ?????
		stream.write("<tr><td align='left' colspan='2' href='" + urlHtmlReplaced + "'>" + DotUL("As HTML") + "</td></tr>")
		stream.write("<tr><td align='left' colspan='2' href='" + urlJsonReplaced + "'>" + DotUL("As JSON") + "</td></tr>")
		stream.write("<tr><td align='left' colspan='2' href='" + urlRdfReplaced + "'>" + DotUL("As RDF") + "</td></tr>")

	# This displays the parameters of the URL and a link allowing to edit them.
	def LegendAddParametersLinks(stream,parameters):
		if len( parameters ) > 0 :
			urlEdit = ModedUrl("edit")
			urlEditReplaced = UrlToSvg( urlEdit )
			stream.write("<tr><td colspan='2' href='" + urlEditReplaced + "' align='left'>" + DotBold(DotUL( "Edit parameters" )) + "</td></tr>" )

		arguments = cgi.FieldStorage()
		for keyParam,valParam in parameters.items():
			try:
				actualParam = arguments[keyParam].value
			except KeyError:
				actualParam = valParam
			stream.write('<tr><td>%s:</td><td>%s</td></tr>' % ( keyParam, DotIt(actualParam) ) )

	#	stream.write("""
	#  rank=sink;
	#  rankdir=LR
	#  node [shape=plaintext]
	# 	""")
	stream.write("node [shape=plaintext]")

	# The first line is a title, the rest, more explanations.
	page_title = page_title.strip()
	page_title_split = page_title.split("\n")
	page_title_first = page_title_split[0]

	page_title_first_wrapped = StrWithBr(page_title_first,2)

	page_title_rest = " ".join( page_title_split[1:] )
	page_title_full =  DotBold(page_title_first_wrapped) + withBrDelim + page_title_rest

	stream.write("""
  subgraph cluster_01 {
    key [shape=none, label=<<table border="1" cellpadding="0" cellspacing="0" cellborder="0">
      <tr><td colspan="2">""" + page_title_full + """</td></tr>
 	""")

	# BEWARE: Port numbers syntax ":8080/" is forbidden in URIs: Strange bug !
	# TODO: The "Top" url should be much more visible.
	stream.write('<tr><td align="left" colspan="2" href="' + topUrl + '">' + DotUL("Top") + '</td></tr>')

	urlDirectAccess = UrlDirectAccess()
	stream.write('<tr><td align="left" colspan="2" href="' + urlDirectAccess + '">' + DotUL("Direct access") + '</td></tr>')

	stream.write("""
      <tr><td align='left' colspan="2">""" + time.strftime("%Y-%m-%d %H:%M:%S") + """</td></tr>
 	""")
	stream.write("""
      <tr><td align='left' >RDF Nodes</td><td>""" + str(len(grph)) + """</td></tr>
 	""")

	LegendAddAlternateDisplayLinks(stream)

	LegendAddParametersLinks(stream,parameters)


	if errMsg != None:
		stream.write('<tr><td align="right" colspan="2">%s</td></tr>' % errMsg)

	if isSubServer:
		urlStop = ModedUrl("stop")
		urlStopReplaced = UrlToSvg( urlStop )
		stream.write('<tr><td colspan="2" href="' + urlStopReplaced + '">' + DotUL("Stop subserver") + '</td></tr>' )
		# TODO: Add an URL for subservers management, instead of simply "stop"
		# Maybe "mode=ctrl".This will list the feeders with their entity_id.
		# So they can be selectively stopped.

	stream.write("""
      </table>>]
  }
 	""")

