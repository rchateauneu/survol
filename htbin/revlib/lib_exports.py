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

# "http://primhillcomputers.com/ontologies/smbshare" = > "smbshare"
def AntiPredicateUri(uri):
	return uri[ len(lib_properties.primns_slash) : ]

# TODO: Est-ce vraiment necessaire ?????????????
# Peut-etre oui, a cause des sockets ?
def WrtAsUtf(out,str):
	out.write( str.encode('utf-8') )

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

# Adds a key value pair at the end of the url with the right delimiter.
# TODO: Checks that the argument is not already there.
# TODO: Most of times, it is used for changing the mode.
def ConcatenateCgi(url,keyvalpair):
	if url.rfind( '?' ) == -1:
		return url + "?" + keyvalpair
	else:
		return url + "&" + keyvalpair

################################################################################
# TODO: THIS IS DUPLICATED.

withBrDelim = '<BR ALIGN="LEFT" />'

# TODO: Set the right criteria for an old Graphviz version.
new_graphiz = True # sys.version_info >= (3,)

# TODO: This is temporary because only old graphviz versions dot not implement that.
def DotBold(str):
	return "<b>%s</b>" % str if new_graphiz else str

def DotUL(str):
	return "<u>%s</u>" % str if new_graphiz else str

################################################################################

# Transforms a RDF graph into a HTML page.
def Grph2Html( page_title, error_msg, isSubServer, parameters, grph, out_dest):
	# TODO: Est-ce necessaire d'utiliser WrtAsUtf au lieu de print() ?
	# Peut-etre oui, a cause des sockets?
	WrtAsUtf( out_dest, "Content-type: text/html\n\n<head>" )

	# TODO: Encode the HTML special characters.
	WrtAsUtf( out_dest, "<title>" + page_title + "</title>")

	# TODO: Essayer de rassembler les literaux relatifs au memes noeuds, pour faire une belle presentation.

	WrtAsUtf( out_dest, ' </head> <body>')

	WrtAsUtf( out_dest,'<table border="1">')

	WrtAsUtf( out_dest,'<tr><td colspan="3"><a href="' + ModedUrl("edit") + '">CGI parameters edition</a></td></tr>')

	for keyParam,valParam in parameters.items():
		WrtAsUtf( out_dest,'<tr><td>' + keyParam + '</td><td colspan="2">' + valParam + '</td></tr>')

	WrtAsUtf( out_dest,'<tr><td colspan="3"><a href="' + ModedUrl("svg") + '">Content as SVG</a></td></tr>')
	WrtAsUtf( out_dest,'<tr><td colspan="3"><a href="' + ModedUrl("rdf") + '">Content as RDF</a></td></tr>')
	WrtAsUtf( out_dest,'<tr><td colspan="3">' + str(len(grph)) + ' nodes</td></tr>')

	if error_msg != None:
		WrtAsUtf( out_dest,'<tr><td colspan="3"><b>' + error_msg + '</b></td></tr>')

	if isSubServer:
		WrtAsUtf( out_dest,'<tr><td colspan="3"><a href="' + ModedUrl("stop") + '">Stop subserver</a></td></tr>')

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
			WrtAsUtf( out_dest, "<tr>" )

			if mustWriteColOne:
				WrtAsUtf( out_dest, '<td rowspan="' + str(cnt_rows) + '"><a href="' + subj_str + '">'+ subj_title +"</a></td>")
				mustWriteColOne = False

			obj_str = str(obj)

			if isinstance( obj , (rdflib.URIRef, rdflib.BNode)):
				obj_title = lib_naming.ParseEntityUri(obj_str)[0]
				WrtAsUtf( out_dest, "<td>" + AntiPredicateUri(str(pred)) + "</td>")
				url_with_mode = ConcatenateCgi( obj_str, "mode=html" )
				WrtAsUtf( out_dest, '<td><a href="' + url_with_mode + '">' + obj_title + "</a></td>")
			else:
				if pred == pc.property_information :
					WrtAsUtf( out_dest, '<td colspan="2">' + obj_str + "</td>")
				else:
					WrtAsUtf( out_dest, '<td>' + AntiPredicateUri(str(pred)) + "</td>")
					WrtAsUtf( out_dest, '<td>' + obj_str + "</td>")

			WrtAsUtf( out_dest, "</tr>")

	WrtAsUtf( out_dest, " </table> </body> </html> ")

################################################################################
# Transforms a RDF graph into a JSON document. From Edouard.

def Grph2Json(page_title, error_msg, isSubServer, parameters, grph, out_dest):
    WrtAsUtf(out_dest, "Content-type: application/json\n\n")

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
    print( json.dumps(graph, indent = 2) )

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
# Petit probleme toutefois avec Graphviz/Dot sous Windows qui nous fait
# des soucis quand un Url contient un ampersand.
#
def Grph2Rdf(grph, out_dest):
	WrtAsUtf( out_dest, "Content-type: text/rdf\n\n")
	# Format support can be extended with plugins,
	# but 'xml', 'n3', 'nt', 'trix', 'rdfa' are built in.

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
#	stream.write("""
#  rank=sink;
#  rankdir=LR
#  node [shape=plaintext]
# 	""")
	stream.write("""
  node [shape=plaintext]
 	""")

	# The first line is a title, the rest, more explanations.
	page_title = page_title.strip()
	page_title_split = page_title.split("\n")
	page_title_first = page_title_split[0]
	page_title_rest = " ".join( page_title_split[1:] )
	page_title_full =  DotBold(page_title_first) + withBrDelim +  page_title_rest

	stream.write("""
  subgraph cluster_01 {
    key [shape=none, label=<<table border="1" cellpadding="0" cellspacing="0" cellborder="0">
      <tr><td colspan="2">""" + page_title_full + """</td></tr>
 	""")

	# BEWARE: Port numbers syntax ":8080/" is forbidden in URIs: Strange bug !
	stream.write('<tr><td align="left" colspan="2" href="' + topUrl + '">' + DotUL("Top") + '</td></tr>')

	stream.write("""
      <tr><td align='left' colspan="2">""" + time.strftime("%Y-%m-%d %H:%M:%S") + """</td></tr>
      <tr><td align='left' >Nodes</td><td>""" + str(len(grph)) + """</td></tr>
 	""")

	# So we can change parameters of this CGI script.
	urlEdit = ModedUrl("edit")
	urlHtml = ModedUrl("html")
	urlJson = ModedUrl("json")
	urlRdf = ModedUrl("rdf")

	urlEditReplaced = UrlToSvg( urlEdit )
	urlHtmlReplaced = UrlToSvg( urlHtml )
	urlJsonReplaced = UrlToSvg( urlJson )
	urlRdfReplaced = UrlToSvg( urlRdf )

	# BEWARE: Port numbers syntax ":8080/" is forbidden in URIs: Strange bug !
	# SO THESE LINKS DO NOT WORK ?????
	stream.write("<tr><td align='left' colspan='2' href='" + urlHtmlReplaced + "'>" + DotUL("As HTML") + "</td></tr>")
	stream.write("<tr><td align='left' colspan='2' href='" + urlJsonReplaced + "'>" + DotUL("As JSON") + "</td></tr>")
	stream.write("<tr><td align='left' colspan='2' href='" + urlRdfReplaced + "'>" + DotUL("As RDF") + "</td></tr>")

	if len( parameters ) > 0 :
		stream.write("<tr><td colspan='2' href='" + urlEditReplaced + "'>" + DotUL( "Parameters edition" ) + "</td></tr>" )

	arguments = cgi.FieldStorage()
	for keyParam,valParam in parameters.items():
		try:
			actualParam = arguments[keyParam].value
		except KeyError:
			actualParam = valParam
		stream.write('<tr><td>%s</td><td>%s</td></tr>' % ( keyParam, actualParam ) )

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

