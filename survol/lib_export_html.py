# Transforms a RDF graph into a HTML page.

import sys
import lib_util
import lib_exports
import lib_naming
import lib_kbase
import entity_dirmenu_only
import lib_properties
from lib_properties import pc

from lib_util import WrtAsUtf
from lib_util import WrtHeader

def WriteParameters(parameters):
	WrtAsUtf('<table border="1">')

	WrtAsUtf('<tr><td colspan="3"><a href="' + lib_exports.ModedUrl("edit") + '">CGI parameters edition</a></td></tr>')

	for keyParam,valParam in parameters.items():
		WrtAsUtf('<tr><td>' + keyParam + '</td><td colspan="2">' + str(valParam) + '</td></tr>')
	WrtAsUtf('</table>')

def WriteOtherUrls(grph):
	WrtAsUtf('<table border="1">')
	WrtAsUtf('<tr><td colspan="3"><a href="' + lib_exports.ModedUrl("svg") + '">Content as SVG</a></td></tr>')
	WrtAsUtf('<tr><td colspan="3"><a href="' + lib_exports.ModedUrl("rdf") + '">Content as RDF</a></td></tr>')
	WrtAsUtf('<tr><td colspan="3">' + str(len(grph)) + ' nodes</td></tr>')
	WrtAsUtf('</table>')


# Similar to entity.py
def WriteScriptsTree(theCgi):

	flagShowAll = False
	rootNode = None

	dictScripts = {}

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

	sys.stderr.write("WriteScriptsTree entity_type=%s\n"%(theCgi.m_entity_type))
	entity_dirmenu_only.DirToMenu(CallbackGrphAdd,rootNode,theCgi.m_entity_type,theCgi.m_entity_id,theCgi.m_entity_host,flagShowAll)

	sys.stderr.write("dictScripts %d\n"%len(dictScripts))


	# Top-level should always be none.
	# TODO: Have another version which formats all cells the same way.
	# For this, have a first pass which counts, at each node, the number of sub-nodes.
	# Then a second pass which uses thiese counts and the current depth,
	# to calculate the rowspan and colspan of each cell.
	# Although elegant, it is not garanteed to work.
	def DisplayLevelTable(subj,depthMenu=1):
		WrtAsUtf('<table border="1">')
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
			WrtAsUtf("<td rowspan='%d'>"%len(mapProps))
			if lib_kbase.IsLink( subj ):
				url_with_mode = lib_util.ConcatenateCgi( subj_str, "mode=html" )
				WrtAsUtf( '<a href="' + url_with_mode + '">' + subj_uniq_title + "</a>")
			else:
				WrtAsUtf( subj_str )
			WrtAsUtf("</td>")

		if not subj_uniq_title:
			for oneProp in mapProps:
				lstObjs = mapProps[oneProp]

				WrtAsUtf('<td>')
				WrtAsUtf('<table>')
				for oneObj in lstObjs:
					if oneObj is None:
						continue
					WrtAsUtf('<tr>')
					WrtAsUtf('<td>')
					try:
						mapPropsSub = dictScripts[oneObj]
						DisplayLevelTable(oneObj,depthMenu)
					except KeyError:
						WrtAsUtf("++"+str(oneObj))
					WrtAsUtf('</td>')
					WrtAsUtf('</tr>')
				WrtAsUtf('</table>')
				WrtAsUtf('</td>')

		WrtAsUtf('</tr>')
		WrtAsUtf( "</table>")

	DisplayLevelTable(None)


	#if entity_type != "":
	#	sys.stderr.write("Entering AddWbemWmiServers\n")
	#	CIM_ComputerSystem.AddWbemWmiServers(grph,rootNode, entity_host, nameSpace, entity_type, entity_id)

	#AddDefaultScripts(grph,rootNode,entity_host)

	# Special case if we are displaying a machine, we might as well try to connect to it.
	#if entity_type == "CIM_ComputerSystem":
	#	AddDefaultScripts(grph,rootNode,entity_id)


def WriteAllObjects(error_msg,isSubServer,grph):
	WrtAsUtf('<table border="1">')

	if error_msg != None:
		WrtAsUtf('<tr><td colspan="3"><b>' + error_msg + '</b></td></tr>')

	if isSubServer:
		WrtAsUtf('<tr><td colspan="3"><a href="' + lib_exports.ModedUrl("stop") + '">Stop subserver</a></td></tr>')

	by_subj = dict()
	for subj, pred, obj in grph:
		# No point displaying some keys if there is no value.
		if pred == pc.property_information :
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

			if lib_kbase.IsLink( obj ):
				obj_title = lib_naming.ParseEntityUri(obj_str)[0]
				WrtAsUtf( "<td>" + lib_exports.AntiPredicateUri(str(pred)) + "</td>")
				url_with_mode = lib_util.ConcatenateCgi( obj_str, "mode=html" )
				WrtAsUtf( '<td><a href="' + url_with_mode + '">' + obj_title + "</a></td>")
			else:
				if pred == pc.property_information :
					WrtAsUtf( '<td colspan="2">' + obj_str + "</td>")
				else:
					WrtAsUtf( '<td>' + lib_exports.AntiPredicateUri(str(pred)) + "</td>")
					WrtAsUtf( '<td>' + obj_str + "</td>")

			WrtAsUtf( "</tr>")

	WrtAsUtf( " </table>")

# pseudoCgi.m_graph = globalGraph
# pseudoCgi.m_page_title = page_title
# pseudoCgi.m_layoutParams = layoutParams
# pseudoCgi.m_parameters = cgiParams
		# lib_export_html.Grph2Html( theCgi, topUrl, errorMsg, isSubServer)
		# lib_export_html.Grph2Html( pageTitle, topUrl, errorMsg, isSubServer, parameters, grph)
# def Grph2Html( page_title, topUrl, error_msg, isSubServer, parameters, grph):
def Grph2Html( theCgi, topUrl, error_msg, isSubServer):
	page_title = theCgi.m_page_title
	grph = theCgi.m_graph
	parameters = theCgi.m_parameters

	WrtHeader('text/html')
	WrtAsUtf( "<head>" )

	# TODO: Encode HTML special characters.
	WrtAsUtf( "<title>" + page_title + "</title>")

	WrtAsUtf( ' </head> <body>')

	WrtAsUtf("Parameters<br/>")
	WriteParameters(parameters)

	# grph_scripts, grph_noscripts = SplitGrphOnScripts(grph)
	WrtAsUtf("Other urls<br/>")
	WriteOtherUrls(grph)

	WrtAsUtf("All objects<br/>")
	WriteAllObjects(error_msg,isSubServer,grph)

	WrtAsUtf("Scripts tree<br/>")
	WriteScriptsTree(theCgi)

	WrtAsUtf( "</body> </html> ")

################################################################################
