# This library helps to generate the output of internal database (RDF-like)
# to the DOT output format, transformed into SVG by Graphviz.

import lib_kbase
import lib_patterns
import lib_naming
import lib_util
from lib_util import UrlToSvg
import lib_properties
from lib_properties import pc
import sys
import time
import cgi
import re
import os
import json
import socket

# "http://primhillcomputers.com/ontologies/smbshare" = > "smbshare"
# TODO: See also PropToShortPropNam()
def AntiPredicateUri(uri):
	return uri[ len(lib_properties.primns_slash) : ]

################################################################################

# Current URL but in edition mode.
# PROBLEM: SI PAS DE ENTITY_ID A EDITER CAR "TOP" ALORS ON REBOUCLE SUR Edit:
# DONC DETECTER LE TYPE DE L'ENTITE EN FOCNTION DU DIRECTORY ET AUCUN SI "TOP".
def ModedUrl(otherMode):
	return lib_util.RequestUriModed(otherMode)

################################################################################
def TruncateInSpace(labText,maxLenLab):
	"""
	This truncates a string to a given length but tries to cut
	at a space position instead of splitting a word.
	"""
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

# To display long strings in HTML-like labels, when Graphviz creates SVG.
maxHtmlTitleLenPerCol = 40
# This is a HTML-like tag for Graphviz only.
withBrDelim = '<BR ALIGN="LEFT" />'

# Inserts "<BR/>" in a string so it can be displayed in a HTML label.
# Beware that it is not really HTML, but only an HTML-like subset.
# See https://www.graphviz.org/doc/info/shapes.html#html
def StrWithBr(aRawStr, colspan = 1):
	# First thing: Cleanup possible HTML tags, otherwise Graphviz stops.
	aStr = aRawStr.replace("<","&lt;").replace(">","&gt;")

	lenStr = len(aStr)
	maxHtmlTitleLen = colspan * maxHtmlTitleLenPerCol
	if lenStr < maxHtmlTitleLen:
		return aStr

	splt = aStr.split(" ")
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

def DotBold(a_str):
	if not a_str: return ""
	return "<b>%s</b>" % a_str

def DotUL(a_str):
	if not a_str: return ""
	return "<u>%s</u>" % a_str

# Do not italicize empty string otherwise "Error: syntax error in line 1 ... <i></i> ..."
def DotIt(a_str):
	if not a_str: return ""
	return "<i>%s</i>" % a_str

################################################################################

dictNodeToUniversalAlias = {}

def NodeToUniversalAlias(anObject):

	def MakeUniversalAliasNoCache(anObj):
		# The prefix of the URL which contain the host name,
		# maybe with a port number, maybe with a WBEM prefix, WMI machine,
		# CGI script etc...
		# is simply replaced by the IP address of the machine.
		# The resulting string is the same for all servers
		# running on the same machine.
		parsed_url = lib_util.survol_urlparse( anObject )
		#sys.stderr.write("MakeUniversalAliasNoCache parsed_url=%s\n"%str(parsed_url))
		# netloc=u'desktop-ni99v8e:8000'
		entity_host = parsed_url.netloc.split(":")[0]
		#sys.stderr.write("MakeUniversalAliasNoCache entity_host=%s\n"%str(entity_host))

		# FIXME: This is very slow.
		if False:
			try:
				# Might throw: socket.gaierror: [Errno 11004] getaddrinfo failed with "entity_host=desktop-ni99v8e"
				entity_ip_addr = lib_util.GlobalGetHostByName(entity_host)
			except:
				entity_ip_addr = entity_host
		else:
			entity_ip_addr = entity_host

		# RFC4343: Hostname are case-insensitive.
		entity_ip_addr = entity_ip_addr.lower()

		# TODO: Many things are calculated several times.
		( labText, subjEntityGraphicClass, entity_id) = lib_naming.ParseEntityUri( anObject, longDisplay = True, force_entity_ip_addr=entity_ip_addr )

		# sys.stderr.write("MakeUniversalAliasNoCache anObject=%s labText=%s\n"%(str(anObject),labText))
		return labText

	try:
		return dictNodeToUniversalAlias[anObject]
	except KeyError:
		uniAlias = MakeUniversalAliasNoCache(anObject)
		dictNodeToUniversalAlias[anObject] = uniAlias
		return uniAlias

################################################################################

# def Graphic_shape():
# 	return "egg"
#
# def Graphic_colorfill():
# 	return "#CCCC33"
#
# def Graphic_colorbg():
# 	return "#CCCC33"
#
# def Graphic_border():
# 	return 0
#
# def Graphic_is_rounded():
# 	return True

#		arrayGraphParams = TypeToGraphParams(type)

NodeJsonNumber = 0

# This models a node as it will be saved to Json.
# TODO: This creates a useless layer of lookup that could be suppressed.
class NodeJson:
	def __init__(self,rdf_node):
		global NodeJsonNumber
		subj_str = str(rdf_node)

		( entity_label, entity_graphic_class, entity_id ) = lib_naming.ParseEntityUri(subj_str, longDisplay=False,force_entity_ip_addr=None)

		self.m_label = entity_label.strip()
		self.m_class = entity_graphic_class

		arrayGraphParams = lib_patterns.TypeToGraphParams(self.m_class)

		# "Graphic_shape","Graphic_colorfill","Graphic_colorbg","Graphic_border","Graphic_is_rounded"
		self.m_color = arrayGraphParams[1]

		# TODO: Display the doc in the module with FromModuleToDoc(importedMod,filDfltText):
		self.m_info_list = [entity_graphic_class]
		self.m_info_dict = dict()
		self.m_index = NodeJsonNumber

		the_survol_url = lib_util.survol_unescape(rdf_node)
		self.m_survol_url = the_survol_url
		self.m_survol_universal_alias = NodeToUniversalAlias(rdf_node)

		NodeJsonNumber += 1 # One more node.

# Transforms a RDF property URIRef into a plain alphanumeric string,
# which can be used as a DOT label or RDF property, or a label string.
# It also returns a dictionary of the key value pairs if any.
# Examples:
# nodePredicate=http://primhillcomputers.com/survol/script?property_description=Data_source
# nodePredicate=http://primhillcomputers.com/survol/user
#
# TODO: See also AntiPredicateUri
def PropToShortPropNamAndDict(nodePredicate):
	strPredicate = str(nodePredicate)
	idxQuestion = strPredicate.rfind("?")
	if idxQuestion == -1:
		dictProperties = None
		# idxLastSlash = strPredicate.rfind("/")
		idxLastSlash = strPredicate.rfind(lib_properties.prefix_terminator)
		shortNam = strPredicate[idxLastSlash+1:]
	else:
		strProperties = strPredicate[idxQuestion+1:]
		vecProperties = strProperties.split("&")
		dictProperties = dict(one_s.split('=',1) for one_s in vecProperties)
		#idxLastSlash = strPredicate.rfind("/",0,idxQuestion)
		idxLastSlash = strPredicate.rfind(lib_properties.prefix_terminator,0,idxQuestion)
		shortNam = strPredicate[idxLastSlash+1:idxQuestion]

	# "sun.boot.class.path"
	# Graphviz just want letters.
	shortNam = shortNam.replace(".","_")
	shortNam = shortNam.replace(" ","_")

	# Some properties, such as "information", are sorted differently by adding a special not-displayed prefix.
	if shortNam.startswith(lib_properties.sortPrefix):
		shortNam = shortNam[len(lib_properties.sortPrefix):]
	assert( shortNam != "" )
	return shortNam, dictProperties

def PropToShortPropNam(nodePredicate):
	return PropToShortPropNamAndDict(nodePredicate)[0]

# Only some scripts and urls are exported to Json.
# The most frequent should come first.
# root=http://rchateau-HP:8000/survol
# url=http://rchateau-HP:8000/survol/class_type_all.py?xid=com.
# url=http://rchateau-HP:8000/survol/objtypes.py
# This must be a tuple because of startswith
urlsForJson = (
	"/entity.py",
	"/entity_wmi.py",
	"/entity_wbem.py",
	"/entity_info_only.py",
	"/objtypes.py",
	"/class_type_all.py",
	"/class_wbem.py",
	"/class_wmi.py",
	# survol.cgi is the special case of the Web server. This prefix normally applies to all scripts.
	"/survolcgi.py?script=/entity.py",
	"/survolcgi.py?script=/entity_info_only.py",
	# TODO: Maybe pass portal_wbem.py and portal_wmi.py ??
)

# This avoids creating a node form some URLs used for returning information. For example:
# http://rchateau-HP:8000/survol/entity_mime.py?xid=CIM_DataFile.Name=C://smh_installer.log&amp;amp;mode=mime:text/plain
# http://rchateau-HP:8000/survol/sources_types/CIM_Directory/file_directory.py?xid=CIM_Directory.Name=C%3A%2F%2Fpkg
def ScriptForJson(url):
	#sys.stderr.write("ScriptForJson url=%s root=%s\n"%(url,lib_util.uriRoot))

	if url.startswith(lib_util.uriRoot):
		# Where the script starts from.
		idxScript = len(lib_util.uriRoot)
		# Other scripts are forbidden.
		return url.startswith(urlsForJson,idxScript)
	# Foreign scripts are OK.
	return True

# What must be avoided: Cross-Origin Request Blocked:
# The Same Origin Policy disallows reading the remote resource at
# http://192.168.0.17/Survol/survol/sources_types/enumerate_CIM_Process.py?xid=.&mode=json.
# (Reason: CORS header 'Access-Control-Allow-Origin' missing)
#
# https://stackoverflow.com/questions/5027705/error-in-chrome-content-type-is-not-allowed-by-access-control-allow-headers
# The body of the reply is base-64 encoded.
def WriteJsonHeader( bufJson, withContentLength = False ):
	arrHeaders = [
		('Access-Control-Allow-Origin','*'),
		('Access-Control-Allow-Methods','POST,GET,OPTIONS'),
		('Access-Control-Allow-Headers','Origin, X-Requested-With, Content-Type, Accept'),
	]

	# It is difficult to calculate the length because the output is encoded
	# in Base64, which takes more room than JSon. And also, at least on Windows,
	# each line gets an extra character ("\n\r" ?).
	# So it is confusing.
	# The reason for adding the length is: When an error is detected, sometimes a second error
	# comes immediately after the one, even if the thread (or process ?) quits.
	#
	# Also, with Chrome and Android, sometimes it is not happy with the length,
	# even if we checked it. It works without the length, except if this is an error message.
	if withContentLength:
		numLines = bufJson.count("\n")
		lenBuf = len(bufJson) + numLines

		arrHeaders.append( ('Content-Length',str(lenBuf) ) )

	lib_util.WrtHeader('application/json', arrHeaders )

	# No text conversion.
	# lib_util.outputHttp.write(bufJson)
	lib_util.WrtAsUtf(bufJson)

# This is a standard for returning errors.
# http://labs.omniti.com/labs/jsend
def WriteJsonError(message):
	WARNING("WriteJsonError message="+message)
	jsonErr = {}
	jsonErr["status"] = "error"
	jsonErr["message"] = message

	# The only case where Content-Length is added.
	WriteJsonHeader(json.dumps(jsonErr, indent=2), True)

	# This closes manually the output, otherwise another thread is triggered
	# and writes another error message, with the header, on the same output.
	# And the client JSON parser does not like that:
	# lib_util.outputHttp.close()

	# "ValueError: I/O operation on closed file"

	sys.exit(0)


# Transforms a RDF graph into a JSON document.
# This returns a graph made of Json objects.
def Grph2Json(page_title, error_msg, isSubServer, parameters, grph):

	# Must be reset to zero between several executions, when run by WSGI.
	global NodeJsonNumber
	NodeJsonNumber = 0

	# It contains a cache because the same nodes may appear several times.
	def NodeToJsonObj(theNod):
		try:
			return NodeToJsonObj.dictNod2Json[theNod]
		except KeyError:
			jsonObj = NodeJson(theNod)
			NodeToJsonObj.dictNod2Json[theNod] = jsonObj
			return jsonObj

	NodeToJsonObj.dictNod2Json = dict()

	links = []
	for subj, pred, obj in grph:
		# This applies only to entity.py : In rendering based on Json, scripts are not displayed as nodes,
		# but in hierarchical menus. The node must not appear at all.

		# TODO: Should probably also eliminate pc.property_rdf_data_nolist2 etc ... See lib_client.
		if pred == pc.property_script:
			DEBUG("continue subj=%s obj=%s",subj,obj)
			continue

		# Normal data scripts are not accepted. This should apply only to file_directory.py and file_to_mime.py
		if not ScriptForJson(subj):
			continue

		if not ScriptForJson(obj):
			continue

		subjObj = NodeToJsonObj(subj)
		subj_id = subjObj.m_survol_url

		propNam = PropToShortPropNam(pred)

		# TODO: BUG: If several nodes for the same properties, only the last one is kept.
		if lib_kbase.IsLink(obj):
			objObj = NodeToJsonObj(obj)
			obj_id = objObj.m_survol_url
			links.extend([{'source': subj_id, 'target': obj_id, 'survol_link_prop': propNam}])

			# TODO: Add the name corresponding to the URL, in m_info_dict so that some elements
			# of the tooltip would be clickable. On the other hand, one just need to merge
			# the nodes relative to the object, by right-clicking.
		elif lib_kbase.IsLiteral(obj):
			if pred == pc.property_information:
				try:
					subjObj.m_info_list.append( str(obj.value) )
				except UnicodeEncodeError:
					# 'ascii' codec can't encode character u'\xf3' in position 17: ordinal not in range(128)
					# https://stackoverflow.com/questions/9942594/unicodeencodeerror-ascii-codec-cant-encode-character-u-xa0-in-position-20
					subjObj.m_info_list.append( obj.value.encode('utf-8') )
			else:
				if isinstance(obj.value, lib_util.six_integer_types) or isinstance(obj.value, lib_util.six_string_types):
					subjObj.m_info_dict[propNam] = obj.value
				else:
					# If the value cannot be serializable to JSON.
					subjObj.m_info_dict[propNam] = type(obj.value).__name__
		else:
			raise "Cannot happen here"

	# Now, this creates the nodes sent as json objects.
	numNodes = len(NodeToJsonObj.dictNod2Json)
	# sys.stderr.write("Grph2Json numNodes=%d\n"%numNodes)
	nodes = [None] * numNodes
	for nod in NodeToJsonObj.dictNod2Json:
		nodObj = NodeToJsonObj.dictNod2Json[nod]
		nod_titl = nodObj.m_label
		nod_id = nodObj.m_index

		# The URL must not contain any HTML entities when in a XML or SVG document,
		# and therefore must be escaped. Therefore they have to be unescaped when transmitted in JSON.
		# This is especially needed for RabbitMQ because the parameter defining its connection name
		# has the form: "Url=LOCALHOST:12345,Connection=127.0.0.1:51748 -> 127.0.0.1:5672"

		# HTTP_MIME_URL
		the_survol_nam = lib_util.survol_unescape(nod_titl) # MUST UNESCAPE HTML ENTITIES !

		# TODO: Use the same object for lookup and Json.
		nodes[nod_id] = {
			'id'                     : nodObj.m_survol_url, # Required by D3
			'name'                   : the_survol_nam,
			# Theoretically, this URL should be HTML unescaped then CGI escaped.
			'survol_url'             : nodObj.m_survol_url, # Duplicate of 'id'
			'survol_universal_alias' : nodObj.m_survol_universal_alias,
			'survol_fill'            : nodObj.m_color,
			'entity_class'           : nodObj.m_class, # TODO: Maybe not needed because also in the URL ?
			'survol_info_list'       : nodObj.m_info_list,
			'survol_info_dict'       : nodObj.m_info_dict
		}

	graph = {}
	graph["page_title"] = page_title
	graph["nodes"] = nodes
	graph["links"] = links

	WriteJsonHeader(json.dumps(graph, indent=2))
	# print(json.dumps(graph, indent=2))

# This returns a tree of scripts, usable as a contextual menu.
# The RDF content is already created, so this keeps only the nodes related to scripts.
# TODO: It would be faster to keep only the tree of scripts. The script "entity.py"
# should have a different output when mode=json.
# It does not return a network but a tree to be displayed in a contextual menu.
# It has a completely different layout as a normal RDF transformed into JSON,
# so probably the URL should be different as well.
# Input example: "http://127.0.0.1:8000/survol/entity.py?xid=CIM_Process.Handle=3812&mode=json"

# TODO: Should add WBEM and WMI ?

def Grph2Menu(page_title, error_msg, isSubServer, parameters, grph):
	# For each node, the subscripts. Therefore it can only be a directory.
	NodesToItems = {}

	# Nodes of scripts which have a parent.
	NodesWithParent = set()

	# Later used to calculate the list of scripts which do not have a parent
	# directory: They will be displayed at the top of the contextual menu.
	SubjectNodes = set()

	NodeToMenuJsonObj = dict()

	# The name of each node.
	NodesToNames = dict()

	for subj, pred, obj in grph:
		if pred == pc.property_script:
			#sys.stderr.write("subj=%s\n"%str(subj))
			#sys.stderr.write("obj=%s\n"%str(obj))
			try:
				NodesToItems[subj].append(obj)
			except KeyError:
				NodesToItems[subj] = [obj]

			if lib_kbase.IsLiteral(obj):
				# This is the name of a subdirectory containing scripts.
				# sys.stderr.write("obj LITERAL=%s\n"%str(subj))
				NodesToNames[obj] = obj

			NodesWithParent.add(obj)
			SubjectNodes.add(subj)
		elif pred == pc.property_information:
			if lib_kbase.IsLiteral(obj):
				#sys.stderr.write("subj=%s\n"%str(subj))
				#sys.stderr.write("obj.value=%s\n"%obj.value)
				NodesToNames[subj] = obj.value
			else:
				raise "Cannot happen here also"
		else:
			pass

	TopLevelNodes = SubjectNodes - NodesWithParent

	# The output result must be sorted.
	def AddStuff(theNodList,depth=0):
		listJsonItems = {}

		for oneRdfNod in theNodList:
			#sys.stderr.write("oneRdfNod=%s\n"%oneRdfNod)
			oneJsonNod = {}
			# This should be the sort key.
			oneJsonNod["name"] = NodesToNames.get(oneRdfNod,"No name")
			# sys.stderr.write( (" " * depth) + "name=%s\n" % (oneJsonNod["name"]) )
			oneJsonNod["url"] = oneRdfNod

			# Maybe it does not have subitems.
			try:
				lstItem = NodesToItems[oneRdfNod]
				oneJsonNod["items"] = AddStuff(lstItem,depth+1)
			except KeyError:
				pass

			listJsonItems[oneRdfNod] = oneJsonNod
		return listJsonItems


	menuJson = AddStuff(TopLevelNodes)

	# sys.stderr.write("menuJson=%s\n"%str(menuJson))

	# There is only one top-level element.
	oneMenuVal = {}
	for oneMenuKey in menuJson:
		oneMenuVal = menuJson[oneMenuKey]["items"]
		break

	#sys.stderr.write("menuJson=%s\n"%str(oneMenuVal))

	WriteJsonHeader(json.dumps(oneMenuVal, sort_keys = True, indent=2))
	# print(json.dumps(oneMenuVal, sort_keys = True, indent=2))

################################################################################

def FontString():

	# fontname: "DejaVuSans.ttf" resolved to: (PangoCairoFcFont) "DejaVu Sans, Book" /usr/share/fonts/dejavu/DejaVuSans.ttf
	# stream.write("node [shape=plaintext fontpath=\"/usr/share/fonts\" fontname=\"DejaVuSans\" ]")

	if lib_util.isPlatformWindows:
		return 'fontname="DejaVu Sans"'
	else:
		# fontname: "DejaVuSans.ttf" resolved to: (PangoCairoFcFont) "DejaVu Sans, Book" /usr/share/fonts/dejavu/DejaVuSans.ttf
		return 'fontpath="/usr/share/fonts" fontname="DejaVuSans"'



htbinPrefixScript = "/survol"

# Link to help page:
# http://www.primhillcomputers.com/ui/help.htm
# http://rchateau-hp:8000/survol/www/help.htm
# http://127.0.0.1/Survol/survol/www/help.htm
# http://primhillcomputers.ddns.net/Survol/survol/www/help.htm
def UrlWWW(pageHtml):
	callingUrl = ModedUrl("")
	#sys.stderr.write("UrlToMergeD3 callingUrl=%s\n"%(callingUrl))
	htbinIdx = callingUrl.find(htbinPrefixScript)

	# We needs the beginning of the URL.
	urlHost = callingUrl[:htbinIdx]
	#sys.stderr.write("UrlToMergeD3 urlHost=%s\n"%(urlHost))

	d3UrlDir = "/survol/www"

	scriptD3Url = urlHost + d3UrlDir + "/" + pageHtml
	#sys.stderr.write("UrlToMergeD3 scriptD3Url=%s\n"%scriptD3Url)
	return scriptD3Url

# This logic should go to lib_client.py

# This returns an URL to the Javascript D3 interface, editing the current data.
def UrlToMergeD3():
	callingUrl = ModedUrl("")
	#sys.stderr.write("UrlToMergeD3 callingUrl=%s\n"%(callingUrl))
	htbinIdx = callingUrl.find(htbinPrefixScript)
	urlWithoutHost = callingUrl[htbinIdx:]
	#sys.stderr.write("UrlToMergeD3 urlWithoutHost=%s\n"%(urlWithoutHost))

	# Consider lib_client.py

	# Maybe this URL is already a merge of B64-encoded URLs:
	htbinPrefixMergeScript = "/survol/merge_scripts.py"
	if urlWithoutHost.startswith(htbinPrefixMergeScript):
		# If so, no need to re-encode.
		urlWithoutHostB64 = urlWithoutHost[len(htbinPrefixMergeScript):]
	else:
		# This works on Windows with cgiserver.py just because the full script starts with "/survol"
		# urlWithoutHostB64 = "?url=" + lib_util.Base64Encode(urlWithoutHost)
		# Complete URL with the host. This is necessary because index.htm has no idea
		# of where the useful part of the URL starts.
		# This works on Linux with Apache.
		urlWithoutHostB64 = "?url=" + lib_util.Base64Encode(callingUrl)
	#sys.stderr.write("UrlToMergeD3 urlWithoutHostB64=%s\n"%urlWithoutHostB64)

	scriptD3Url = UrlWWW("index.htm") + urlWithoutHostB64
	#sys.stderr.write("UrlToMergeD3 scriptD3Url=%s\n"%scriptD3Url)
	return scriptD3Url

# In SVG/Graphiz documents, this writes the little rectangle which contains various information.
def WriteDotLegend( page_title, topUrl, errMsg, isSubServer, parameters, parameterized_links, stream, grph ):

	# This allows to enter directly the URL parameters, so we can access directly an object.
	# This will allow to choose the entity type, and each parameter of the URL (Taken
	# from the ontology). It also edits the parameters of the current URL.
	# TODO: MUST FINISH THIS.
	#def UrlDirectAccess():
	#	return "direct_access.py"

	# This adds links which can display the same content in a different output format.
	def LegendAddAlternateDisplayLinks(stream):
		# So we can change parameters of this CGI script.
		urlHtml = ModedUrl("html")
		urlJson = ModedUrl("json")
		urlRdf = ModedUrl("rdf")
		urlD3 = UrlToMergeD3()

		# Stupid replacement of dot: "\\" transformed into "\"
		# Fix for : "http://rchateau-hp:8000/survol/class_wmi.py?xid=\\machine\root\CIMV2%3ACIM_Directory.&mode=html"
		def UrlForDot(mdUrl):
			mdUrl = mdUrl.replace("\\\\","\\\\\\")
			return UrlToSvg(mdUrl)

		stream.write("<tr><td colspan='4'><table border='0'>")
		stream.write(
			"<tr>"
			"<td>(</td>"
			"<td align='left' href='" + UrlForDot( urlHtml ) + "'>" + DotUL("HTML") + "</td>"
			"<td>,</td>"
			"<td align='left' href='" + UrlForDot( urlJson ) + "'>" + DotUL("JSON") + "</td>"
			"<td>,</td>"
			"<td align='left' href='" + UrlForDot( urlRdf ) + "'>" + DotUL("RDF") + "</td>"
			"<td>,</td>"
			"<td align='left' href='" + UrlForDot( urlD3 ) + "'>" + DotUL("D3") + "</td>"
			"<td>)</td></tr>"
		)
		stream.write("</table></td></tr>")



	# This displays the parameters of the URL and a link allowing to edit them.
	# It assumes that it writes in the middle of a table with two columns.
	def LegendAddParametersLinks(stream, parameters, parameterized_links):

		if parameters :
			urlEdit = ModedUrl("edit")
			urlEditReplaced = UrlToSvg( urlEdit )
			stream.write("<tr><td colspan='4' href='" + urlEditReplaced + "' align='left'>" + DotBold(DotUL( "Edit script parameters" )) + "</td></tr>" )

			arguments = cgi.FieldStorage()
			for keyParam,valParam in parameters.items():
				try:
					actualParam = arguments[keyParam].value
				except KeyError:
					actualParam = valParam
				stream.write('<tr><td colspan="2">%s:</td><td colspan="2">%s</td></tr>' % ( keyParam, DotIt(actualParam) ) )

		# We want to display links associated to the parameters.
		# The use case is "Prev/Next" when paging between many values.
		# This could be nicely modelled by just specifying special set of values,
		# and the links would be calculated here.
		# For example: { "next" : { "index": curr + 80 }, "prev" : { "index": curr - 80 } }
		# This simplifies the edition in Json.
		# It might also simplify formatting.
		# There will be a similar piece of code in Javascript and plain HTML:
		# (1) The calling script provides the values to CgiEnv.
		# (2) A method in CgiEnv calculates the URLS and returns a map
		# of { "label":"urls" }

		for urlLabel in parameterized_links:
			paramUrl = parameterized_links[urlLabel]
			stream.write("<tr><td colspan='4' href='" + paramUrl + "' align='left'>" + DotBold(DotUL( urlLabel )) + "</td></tr>" )

	def LegendFooter():

		urlHelp = UrlToSvg(UrlWWW("help.htm"))

		stream.write("<tr>")
		stream.write('<td align="left" href="' + topUrl + '">' + DotBold(DotUL("Home")) + '</td>')
		urlEdtConfiguration = lib_util.uriRoot + "/edit_configuration.py"
		stream.write("<td href='"+urlEdtConfiguration+"' align='left'>" + DotBold(DotUL( "Setup" )) + "</td>")
		urlEdtCredentials = lib_util.uriRoot + "/edit_credentials.py"
		stream.write("<td href='"+urlEdtCredentials+"' align='left'>" + DotBold(DotUL( "Credentials" )) + "</td>")
		stream.write("<td href='"+urlHelp+"' align='left'>" + DotBold(DotUL( "Help" )) + "</td>")
		stream.write("</tr>" )



	# stream.write("node [shape=plaintext fontname=\"DejaVu Sans\" ]")
	# fontname: "DejaVuSans.ttf" resolved to: (PangoCairoFcFont) "DejaVu Sans, Book" /usr/share/fonts/dejavu/DejaVuSans.ttf
	# stream.write("node [shape=plaintext fontpath=\"/usr/share/fonts\" fontname=\"DejaVuSans\" ]")
	stream.write("node [shape=plaintext %s ]" % FontString() )

	# The first line is a title, the rest, more explanations.
	# The first line also must be wrapped if it is too long.
	# TODO: This logic should be factorised because it seems to be used when merging ?

	(page_title_first,page_title_rest) = lib_util.SplitTextTitleRest(page_title)

	page_title_first_wrapped = StrWithBr(page_title_first,2)
	page_title_rest_wrapped = StrWithBr(page_title_rest,2)
	page_title_full =  DotBold(page_title_first_wrapped) + withBrDelim + page_title_rest_wrapped

	stream.write("""
  subgraph cluster_01 {
    subgraph_cluster_key [shape=none, label=<<table border="1" cellpadding="0" cellspacing="0" cellborder="0">""")

	stream.write("<tr><td colspan='4'>" + page_title_full + "</td></tr>" )
	LegendAddAlternateDisplayLinks(stream)
	LegendAddParametersLinks(stream,parameters,parameterized_links)

	LegendFooter()

	# The error message could be None or an empty string.
	if errMsg:
		fullErrMsg = DotBold("Error: ") + errMsg
		stream.write('<tr><td align="left"  balign="left" colspan="2">%s</td></tr>' % StrWithBr(fullErrMsg,2))

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

