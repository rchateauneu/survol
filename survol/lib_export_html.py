"""
	Transforms an internal graph into a HTML page.
"""
import os
import sys
import lib_util
import lib_mime
import lib_exports
import lib_patterns
import lib_naming
import lib_kbase
import entity_dirmenu_only
import lib_properties
from lib_properties import pc
from lib_util import WrtAsUtf
from sources_types import CIM_ComputerSystem

# TODO: Use descriptions provided by lib_bookmark.py

# This does not change the existing mode if there is one.
# Otherwise it could erase the MIME type.
def UrlInHtmlMode(anUrl):
	urlMode = lib_util.GetModeFromUrl(anUrl)
	# sys.stderr.write("UrlInHtmlMode anUrl=%s urlMode=%s\n"%(anUrl,urlMode))
	if urlMode:
		return anUrl
	else:
		return lib_util.AnyUriModed(anUrl, "html")

def WriteScriptInformation(theCgi,gblCgiEnvList):
	"""
		This displays general information about this script and the object if there is one.
	"""
	sys.stderr.write("WriteScriptInformation entity_type=%s\n"%(theCgi.m_entity_type))

	# This is already called in lib_common, when creating CgiEnv.
	# It does not matter because this is very fast.
	callingUrl = lib_util.RequestUri()
	( entity_label, entity_graphic_class, entity_id ) = lib_naming.ParseEntityUri(callingUrl,longDisplay=True)
	sys.stderr.write("entity_label=%s entity_graphic_class=%s entity_id=%s\n"%( entity_label, entity_graphic_class, entity_id ))

	# WrtAsUtf('<table class="list_of_merged_scripts">')
	WrtAsUtf('<table border="0">')
	if len(gblCgiEnvList):
		sys.stderr.write("gblCgiEnvList=%s\n"%str(gblCgiEnvList))
		# This step is dedicated to the merging of several scripts.

		WrtAsUtf("<tr align=left><td colspan=2 align=left><h2>Fusion of data from %d scripts</h2></td></tr>"%len(gblCgiEnvList))
		for aCgiEnv in gblCgiEnvList:
			sys.stderr.write("aCgiEnv=%s\n"%str(aCgiEnv))
			sys.stderr.write("aCgiEnv.m_page_title=%s\n"%str(aCgiEnv.m_page_title))
			sys.stderr.write("aCgiEnv.m_calling_url=%s\n"%str(aCgiEnv.m_calling_url))
			(page_title_first,page_title_rest) = lib_util.SplitTextTitleRest(aCgiEnv.m_page_title)
			WrtAsUtf("<tr><td><a href='%s'>%s</td><td><i>%s</i></td></tr>"%(aCgiEnv.m_calling_url,page_title_first,page_title_rest))

	else:
		(page_title_first,page_title_rest) = lib_util.SplitTextTitleRest(theCgi.m_page_title)
		WrtAsUtf("<tr><td colspan=2><h2>%s</h2></td></tr>"%(page_title_first))
		if page_title_rest:
			WrtAsUtf("<tr><td colspan=2>%s</td></tr>"%(page_title_rest))

	WrtAsUtf('</table>')

	if theCgi.m_entity_type:
		# WrtAsUtf('m_entity_id: %s<br>'%(theCgi.m_entity_id))

		WrtAsUtf('<table class="table_script_information">')

		entity_module = lib_util.GetEntityModule(theCgi.m_entity_type)
		entDoc = entity_module.__doc__
		if not entDoc:
			entDoc = ""

		urlClass = lib_util.EntityClassUrl(theCgi.m_entity_type)
		urlClass_with_mode = UrlInHtmlMode( urlClass )
		WrtAsUtf(
		"""
		<tr>
			<td><a href='%s'>%s</a></td>
			<td>%s</td>
		</tr>
		"""
		% ( urlClass_with_mode, theCgi.m_entity_type, entDoc ))

		for keyProp in theCgi.m_entity_id_dict:
			keyVal = theCgi.m_entity_id_dict[keyProp]

			WrtAsUtf(
			"""
			<tr>
				<td>%s</td>
				<td>%s</td>
			</tr>
			"""
			% ( keyProp, keyVal ))

		WrtAsUtf('</table>')


def WriteParameters(theCgi):
	"""
		This displays the parameters of the script and provide an URL to edit them.
	"""

	import lib_edition_parameters

	formAction = os.environ['SCRIPT_NAME']

	lib_edition_parameters.FormEditionParameters(formAction,theCgi)

def WriteOtherUrls(topUrl):
	"""
		This displays the URL to view the same document, in other ouput formats.
	"""

	WrtAsUtf('<table class="other_urls">')

	if topUrl:
		topUrl_with_mode = UrlInHtmlMode( topUrl )
		WrtAsUtf("""
		<tr><td align="left" colspan="2"><a href="%s"><b>Home</b></a></td></tr>
		""" % topUrl_with_mode )

	# Because Graphviz is not available on OVH platform.
	if not lib_util.modeOVH:
		WrtAsUtf("""
		<tr>
			<td class="other_urls"><a href="%s">SVG format</a></td>
			<td>Graphviz&trade; generated</td>
		</tr>
		""" % lib_exports.ModedUrl("svg") )

	WrtAsUtf("""
	<tr>
		<td class="other_urls"><a href="%s">RDF format</a></td>
		<td>Semantic Web, OWL standard / Prot&eacute;g&eacute;&trade;...</td>
	</tr>
	""" % lib_exports.ModedUrl("rdf") )

	urlD3 = lib_exports.UrlToMergeD3()

	WrtAsUtf("""
	<tr>
		<td class="other_urls"><a href="%s">D3</a></td>
		<td>Javascript D3 library</td>
	</tr>
	""" % urlD3 )

	host_wbem_wmi = lib_util.currentHostname

	# This callback receives a RDF property (WBEM or WMI) and a map
	# which represents the CIM links associated to the current object.
	def WMapToHtml(theMap,propData):
		sys.stderr.write("WMapToHtml len=%d\n"%len(theMap))
		for urlSubj in theMap:
			(subjText, subjEntityGraphClass, subjEntityId) = lib_naming.ParseEntityUri( lib_util.urllib_unquote(urlSubj) )
			WrtAsUtf("<tr>")
			WrtAsUtf("<td valign='top'><a href='%s'>%s</a></td>"%( str(urlSubj), subjText ) )
			WrtAsUtf("<td>")
			WrtAsUtf("<table>")
			for theProp, urlObj in theMap[urlSubj]:
				WrtAsUtf("<tr>")
				propNam = lib_exports.PropToShortPropNam(theProp)
				WrtAsUtf("<td><i>%s</i></td>"%propNam)
				if lib_kbase.IsLiteral(urlObj):
					WrtAsUtf("<td>%s</td>"%( str(urlObj) ) )
				else:
					(objText, objEntityGraphClass, objEntityId) = lib_naming.ParseEntityUri( lib_util.urllib_unquote(urlObj) )
					WrtAsUtf("<td><a href='%s'>%s</a></td>"%( str(urlObj), objText ) )
				WrtAsUtf("</tr>")
			WrtAsUtf("</table>")
			WrtAsUtf("</td>")
		WrtAsUtf("</tr>")

	callingUrl = lib_util.RequestUri()
	( entity_label, entity_type, entity_id ) = lib_naming.ParseEntityUri(callingUrl,longDisplay=True)
	nameSpace = ""

	mapWbem = CIM_ComputerSystem.AddWbemServers(host_wbem_wmi, nameSpace, entity_type, entity_id)
	WMapToHtml(mapWbem,pc.property_wbem_data)
	mapWmi = CIM_ComputerSystem.AddWmiServers(host_wbem_wmi, nameSpace, entity_type, entity_id)
	WMapToHtml(mapWmi,pc.property_wmi_data)
	mapSurvol = CIM_ComputerSystem.AddSurvolServers(host_wbem_wmi, nameSpace, entity_type, entity_id)
	WMapToHtml(mapSurvol,pc.property_survol_agent)

	WrtAsUtf('</table>')



def WriteScriptsTree(theCgi):
	"""
		This displays the tree of accessible Python scripts for the current object.
		It is displayed as a recursive table. A similar logic is used in entity.
		(Where the tree is displayed as a tree of SVG nodes) and in index.htm
		(With a contextual menu).
	"""

	flagVal = theCgi.GetParameters( lib_util.paramkeyShowAll )
	sys.stderr.write("WriteScriptsTree flagVal=%s\n"%flagVal)
	# This happens when merging scripts.
	if flagVal == "":
		flagShowAll = 0
	else:
		flagShowAll = int(flagVal)

	rootNode = None

	dictScripts = {}

	# This function is called for each script which applies to the given entity.
	# It receives a triplet: (subject,property,object) and the depth in the tree.
	# Here, this simply stores the scripts in a map, which is later used to build
	# the HTML display. The depth is not used yet.
	def CallbackGrphAdd( trpl, depthCall ):
		subj,prop,obj = trpl

		# sys.stderr.write("CallbackGrphAdd subj=%s\n"%str(subj))
		try:
			mapProps = dictScripts[subj]
			try:
				lstObjs = mapProps[prop].append(obj)
			except KeyError:
				mapProps[prop] = [obj]
		except KeyError:
			dictScripts[subj] = { prop : [obj ] }

	sys.stderr.write("WriteScriptsTree entity_type=%s flagShowAll=%d\n"%(theCgi.m_entity_type,flagShowAll))
	entity_dirmenu_only.DirToMenu(CallbackGrphAdd,rootNode,theCgi.m_entity_type,theCgi.m_entity_id,theCgi.m_entity_host,flagShowAll)

	sys.stderr.write("dictScripts %d\n"%len(dictScripts))


	def DisplayLevelTable(subj,depthMenu=1):
		"""
			Top-level should always be none.
			TODO: Have another version which formats all cells the same way.
			For this, have a first pass which counts, at each node, the number of sub-nodes.
			Then a second pass which uses thiese counts and the current depth,
			to calculate the rowspan and colspan of each cell.
			Although elegant, it is not garanteed to work.
		"""
		WrtAsUtf('<table class="table_scripts_titles">')
		try:
			mapProps = dictScripts[subj]
		except KeyError:
			return

		def ExtractTitleFromMapProps(mapProps):
			if len(mapProps) != 1:
				return None
			for oneProp in mapProps:
				if oneProp != pc.property_information:
					return None

				lstStr = mapProps[oneProp]
				if len(lstStr) != 1:
					return None
				retStr = lstStr[0]
				if lib_kbase.IsLink( retStr ):
					return None

				return str(retStr)

		WrtAsUtf('<tr>')
		depthMenu += 1

		subj_uniq_title = ExtractTitleFromMapProps(mapProps)

		if subj:
			subj_str = str(subj)
			WrtAsUtf("<td valign='top' rowspan='%d'>"%len(mapProps))
			if lib_kbase.IsLink( subj ):
				url_with_mode = UrlInHtmlMode( subj_str )
				if subj_uniq_title:
					subj_uniq_title_not_none = subj_uniq_title
				else:
					subj_uniq_title_not_none = "No title"
				WrtAsUtf( '<a href="' + url_with_mode + '">' + subj_uniq_title_not_none + "</a>")
			else:
				WrtAsUtf( subj_str )
			WrtAsUtf("</td>")

		if not subj_uniq_title:
			for oneProp in mapProps:
				lstObjs = mapProps[oneProp]

				WrtAsUtf('<td>')
				WrtAsUtf('<table class="table_scripts_links">')
				for oneObj in lstObjs:
					if oneObj is None:
						continue
					WrtAsUtf('<tr>')
					WrtAsUtf('<td>')
					try:
						mapPropsSub = dictScripts[oneObj]
						DisplayLevelTable(oneObj,depthMenu)
					except KeyError:
						WrtAsUtf("Script error: "+str(oneObj))
					WrtAsUtf('</td>')
					WrtAsUtf('</tr>')
				WrtAsUtf('</table>')
				WrtAsUtf('</td>')

		WrtAsUtf('</tr>')
		WrtAsUtf( "</table>")

	DisplayLevelTable(None)

def WriteErrors(error_msg,isSubServer):
	if error_msg or isSubServer:
		# TODO: Use style-sheets.
		WrtAsUtf('<table border="0">')

		if error_msg:
			WrtAsUtf('<tr><td bgcolor="#DDDDDD" align="center" color="#FF0000"><b></b></td></tr>')
			WrtAsUtf('<tr><td bgcolor="#DDDDDD"><b>ERROR MESSAGE:%s</b></td></tr>' % error_msg)

		if isSubServer:
			WrtAsUtf('<tr><td><a href="' + lib_exports.ModedUrl("stop") + '">Stop subserver</a></td></tr>')
		WrtAsUtf( " </table><br>")

# TODO: When the objects have the same column names, displaying could be optimised
# into a single table without repetition of the same titles.

def WriteAllObjects(grph):
	"""
		This displays all the objects returend by this scripts.
		Other scripts are not here, so we do not have to eliminate them.
		This is therefore simpler than in the SVG (Graphviz) output,
		where all objects are mixed together.
	"""


	# This groups data by subject, then predicate, then object.
	dictClassSubjPropObj = dict()

	# TODO: Group objects by type, then display the count, some info about each type etc...
	for aSubj, aPred, anObj in grph:
		# No point displaying some keys if there is no value.
		if aPred == pc.property_information :
			try:
				if str(anObj) == "":
					continue
			# 'ascii' codec can't encode character u'\xf3' in position 17: ordinal not in range(128)
			# u'SDK de comprobaci\xf3n de Visual Studio 2012 - esn'
			except UnicodeEncodeError:
				exc = sys.exc_info()[1]
				sys.stderr.write("Exception %s\n"%str(exc))
				continue

		subj_str = str(aSubj)
		( subj_title, entity_graphic_class, entity_id ) = lib_naming.ParseEntityUri(subj_str)

		try:
			dictSubjPropObj = dictClassSubjPropObj[entity_graphic_class]
			try:
				dictPred = dictSubjPropObj[aSubj]
				try:
					dictPred[aPred].append(anObj)
				except KeyError:
					# First time this object has this predicate.
					dictPred[aPred] = [ anObj ]
			except KeyError:
				# First time we see this object.
				dictSubjPropObj[aSubj] = { aPred : [ anObj ] }
		except KeyError:
			# First object of this class.
			dictClassSubjPropObj[entity_graphic_class] = { aSubj: { aPred : [ anObj ] } }

	# Group objects by class.
	# Display list of classes with an indexs and a link to the class.
	# "NO TITLE" is wrong

	# TODO: Create a "difference mode". Periodic display, of only the difference between successive data sets.
	# Ajouter mode "difference": On recalcule periodiquement et on affiche la difference.

	# No need to use natural sort, because these are no filenames or strings containing numbres.
	for entity_graphic_class in sorted(dictClassSubjPropObj):

		urlClass = lib_util.EntityClassUrl(entity_graphic_class)
		urlClass_with_mode = UrlInHtmlMode( urlClass )
		WrtAsUtf("<h3>Class <a href='%s'>%s</a></h3>"%(urlClass_with_mode,entity_graphic_class))
		dictSubjPropObj = dictClassSubjPropObj[entity_graphic_class]

		DispClassObjects(dictSubjPropObj)

# Apparently, a problem is that "%" gets transformed into an hexadecimal number, preventing decoding.
def DesHex(theStr):
	theStr = lib_util_HTMLParser().unescape(theStr)
	return theStr.replace("%25","%").replace("%2F","/").replace("%5C","\\").replace("%3A",":")

# TODO: Scripts should be merged together on demand.
# This could be achieved by filtering href clicks with javascript. With CSS ?

def DispClassObjects(dictSubjPropObj):
	listPropsTdDoubleColSpan = [pc.property_information,pc.property_rdf_data_nolist2,pc.property_rdf_data_nolist1]

	WrtAsUtf('<table class="class_objects">')

	# The subjects must be sorted by their title.
	lstTuplesSubjects = []
	for aSubj in dictSubjPropObj:
		subj_str = str(aSubj)
		( subj_title, entity_graphic_class, entity_id ) = lib_naming.ParseEntityUri(subj_str)
		lstTuplesSubjects.append((aSubj,subj_str,subj_title, entity_graphic_class, entity_id))

	# Sorted by the title of the subject, which is the third value of the tuple.
	lib_util.natural_sort_list(lstTuplesSubjects,key=lambda tup: tup[2])

	# Now it iterates on the sorted list.
	# This reuses all the intermediate values.
	for aSubj,subj_str,subj_title, entity_graphic_class, entity_id in lstTuplesSubjects:
		dictPred = dictSubjPropObj[aSubj]

		arrayGraphParams = lib_patterns.TypeToGraphParams(entity_graphic_class)
		# "Graphic_shape","Graphic_colorfill","Graphic_colorbg","Graphic_border","Graphic_is_rounded"
		colorClass = arrayGraphParams[1]

		# Total number of lines.
		cntPreds = 0
		for aPred in dictPred:
			lstObjs = dictPred[aPred]
			cntPreds += len(lstObjs)

		mustWriteColOneSubj = True

		subj_str_with_mode = UrlInHtmlMode( subj_str )

		# The predicates, i.e. the properties associated a subject with an object,
		# must be alphabetically sorted.
		for aPred in lib_util.natural_sorted(dictPred):
			lstObjs = dictPred[aPred]

			predStr = lib_exports.AntiPredicateUri(str(aPred))
			cntObjs = len(lstObjs)
			mustWriteColOnePred = True

			# The objects must be sorted by title.
			lstTuplesObjs = []
			for anObj in lstObjs:
				obj_str = str(anObj)
				obj_str = DesHex(obj_str)
				obj_title = lib_naming.ParseEntityUri(obj_str)[0]
				lstTuplesObjs.append((anObj,obj_str,obj_title))

			# Sorted by the title of the object, which is the third value of the tuple.
			lib_util.natural_sort_list(lstTuplesObjs,key=lambda tup: tup[2])

			for anObj,obj_str,obj_title in lstTuplesObjs:

				WrtAsUtf( '<tr bgcolor="%s">' % colorClass )

				if mustWriteColOneSubj:
					WrtAsUtf(
						'<td valign="top" rowspan="%s"><a href="%s">%s</a></td>'
						% (str(cntPreds), subj_str_with_mode, subj_title ) )
					mustWriteColOneSubj = False

				if mustWriteColOnePred:
					if aPred not in listPropsTdDoubleColSpan :
						WrtAsUtf( '<td valign="top" rowspan="%s">%s</td>' % (str(cntObjs), predStr) )
					mustWriteColOnePred = False

				if aPred in listPropsTdDoubleColSpan:
					colSpan = 2
				else:
					colSpan = 1

				dispMimeUrls = True

				WrtAsUtf( '<td colspan="%d">' %(colSpan))
				if dispMimeUrls:
					if lib_kbase.IsLink( anObj ):
						objStrClean = lib_util.UrlNoAmp(obj_str)
						mimeType = lib_mime.GetMimeTypeFromUrl(objStrClean)
						if mimeType:
							if mimeType.startswith("image/"):
								WrtAsUtf(
									"""<a href="%s"><img src="%s" alt="%s" height="42" width="42"></a>"""
									% (obj_str,obj_str,obj_title)
								)
							else:
								WrtAsUtf( """<a href="%s">%s</a>""" % (obj_str,obj_title) )
						else:
							url_with_mode = lib_util.AnyUriModed(obj_str, "html")
							WrtAsUtf( """<a href="%s">%s</a>""" % (url_with_mode,obj_title) )
					else:
						WrtAsUtf( '%s' %(obj_str))
				else:
					if lib_kbase.IsLink( anObj ):
						url_with_mode = UrlInHtmlMode( obj_str )
						WrtAsUtf( '<a href="%s">%s</a>' % (url_with_mode,obj_title))
					else:
						WrtAsUtf( '%s' %(obj_str))


				WrtAsUtf( "</td>")

				WrtAsUtf( "</tr>")

	WrtAsUtf( " </table>")

def DisplayHtmlTextHeader(page_title):
	"""
	This is the common Survol header, ideally for all HTML documents.
	"""

	lib_util.WrtHeader('text/html')
	WrtAsUtf( "<head>" )

	# TODO: Encode HTML special characters.
	WrtAsUtf( "<title>%s</title>" % page_title)

	# The href must be absolute so it will work with any script.
	# We must calculate its prefix.
	# In the mean time, this solution adapts to our three kind of different hosting types:
	# - OVH mutialised hosting, with a specific CGI script survol.cgi
	# - With the Python class HttpServer as Web server.
	# - Hosted with Apache.

	WrtAsUtf(
		"""
		<link rel='stylesheet' type='text/css' href=/ui/css/html_exports.css>
		<link rel='stylesheet' type='text/css' href='/survol/www/css/html_exports.css'>
		<link rel='stylesheet' type='text/css' href='../survol/www/css/html_exports.css'>
		""")

	WrtAsUtf('</head>')


def DisplayHtmlTextFooter():
	"""
	This is the common Survol footer.
	"""

	wrtFmt = """
	<br>
	<table width="100%"><tr>
	<td><a href="index.htm">Survol home</a></td>
	<td><a href="edit_credentials.py">Credentials</a></td>
	<td><a href="edit_configuration.py">Configuration</a></td>
	<td align="right">&copy; <a href="http://www.primhillcomputers.com">Primhill Computers</a> 2017</i></td>
	</tr></table>
	"""

	# This needs a directory whichdepends on the HTTP hosting.
	urlIndex = lib_exports.UrlWWW("index.htm")

	# With this trick, the footer can be used as is in HTML pages.
	wrtTxt = wrtFmt.replace("index.htm",urlIndex)
	WrtAsUtf(wrtTxt)

def Grph2Html( theCgi, topUrl, error_msg, isSubServer,gblCgiEnvList):
	"""
		This transforms an internal data graph into a HTML document.
	"""
	page_title = theCgi.m_page_title
	grph = theCgi.m_graph

	DisplayHtmlTextHeader(page_title)

	WrtAsUtf('<body>')

	WriteScriptInformation(theCgi,gblCgiEnvList)

	WriteErrors(error_msg,isSubServer)

	# WrtAsUtf("<h2>Objects</h2>")
	WriteAllObjects(grph)

	if len(theCgi.m_parameters) > 0:
		WrtAsUtf("<h2>Script parameters</h2>")
		WriteParameters(theCgi)

	# Scripts do not apply when displaying a class.
	# TODO: When in a enumerate script such as enumerate_CIM_LogicalDisk.py,
	# it should assume the same: No id but a class.
	if(theCgi.m_entity_type == "") or (theCgi.m_entity_id!=""):
		WrtAsUtf("<h2>Related data scripts</h2>")
		WriteScriptsTree(theCgi)

	WrtAsUtf("<h2>Other related urls</h2>")
	WriteOtherUrls(topUrl)

	DisplayHtmlTextFooter()

	WrtAsUtf("</body>")

	WrtAsUtf("</html> ")

################################################################################
