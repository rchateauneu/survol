"""
	Transforms an internal graph into a HTML page.
"""

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
	"""
		This displays the parameters of the script and provide an URL to edit them.
	"""
	WrtAsUtf('<table border="1">')

	WrtAsUtf('<tr><td colspan="3"><a href="' + lib_exports.ModedUrl("edit") + '">CGI parameters edition</a></td></tr>')

	for keyParam,valParam in parameters.items():
		WrtAsUtf('<tr><td>' + keyParam + '</td><td colspan="2">' + str(valParam) + '</td></tr>')
	WrtAsUtf('</table>')

def WriteOtherUrls():
	"""
		This displays the URL to view the same document, in other ouput formats.
	"""
	WrtAsUtf('<table border="1">')
	WrtAsUtf('<tr><td colspan="3"><a href="' + lib_exports.ModedUrl("svg") + '">Content as SVG</a></td></tr>')
	WrtAsUtf('<tr><td colspan="3"><a href="' + lib_exports.ModedUrl("rdf") + '">Content as RDF</a></td></tr>')
	WrtAsUtf('</table>')



def WriteScriptsTree(theCgi):
	"""
		This displays the tree of accessible Python scripts for the current object.
		It is dsiplayed as a recusive tab. A similar logic is used in entity.y
		(Where the tree is displayed as a tree of SVG nodes) and in index.htm
		(With a contextual menu).
	"""
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


	def DisplayLevelTable(subj,depthMenu=1):
		"""
			Top-level should always be none.
			TODO: Have another version which formats all cells the same way.
			For this, have a first pass which counts, at each node, the number of sub-nodes.
			Then a second pass which uses thiese counts and the current depth,
			to calculate the rowspan and colspan of each cell.
			Although elegant, it is not garanteed to work.
		"""
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
	"""
		This displays all the objects returend by this scripts.
		Other scripts are not here, so we do not have to eliminate them.
		This is therefore simpler than in the SVG (Graphviz) output,
		where all objects are mixed together.
	"""
	WrtAsUtf('<table border="1">')

	if error_msg != None:
		WrtAsUtf('<tr><td colspan="3"><b>' + error_msg + '</b></td></tr>')

	if isSubServer:
		WrtAsUtf('<tr><td colspan="3"><a href="' + lib_exports.ModedUrl("stop") + '">Stop subserver</a></td></tr>')


	# This groups data by subject, then predicate, then object.
	dictSubjPropObj = dict()

	# TODO: Group objects by type.
	for aSubj, aPred, anObj in grph:
		# No point displaying some keys if there is no value.
		if aPred == pc.property_information :
			if str(anObj) == "":
				continue

		try:
			dictPred = dictSubjPropObj[aSubj]
			try:
				dictPred[aPred].append(anObj)
			except KeyError:
				dictPred[aPred] = [ anObj ]
		except KeyError:
			dictSubjPropObj[aSubj] = { aPred : [ anObj ] }


	for aSubj in dictSubjPropObj:
		dictPred = dictSubjPropObj[aSubj]

		subj_str = str(aSubj)
		subj_title = lib_naming.ParseEntityUri(subj_str)[0]

		# Total number of lines.
		cntPreds = 0
		for aPred in dictPred:
			lstObjs = dictPred[aPred]
			cntPreds += len(lstObjs)

		mustWriteColOneSubj = True

		for aPred in dictPred:
			lstObjs = dictPred[aPred]

			predStr = lib_exports.AntiPredicateUri(str(aPred))
			cntObjs = len(lstObjs)
			mustWriteColOnePred = True

			for anObj in lstObjs:

				WrtAsUtf( "<tr>" )

				if mustWriteColOneSubj:
					WrtAsUtf( '<td rowspan="' + str(cntPreds) + '"><a href="' + subj_str + '">'+ subj_title + "</a></td>")
					mustWriteColOneSubj = False

				if mustWriteColOnePred:
					if aPred != pc.property_information :
						WrtAsUtf( '<td rowspan="' + str(cntObjs) + '">'+ predStr + "</td>")
					mustWriteColOnePred = False

				obj_str = str(anObj)

				if lib_kbase.IsLink( anObj ):
					obj_title = lib_naming.ParseEntityUri(obj_str)[0]
					url_with_mode = lib_util.ConcatenateCgi( obj_str, "mode=html" )
					WrtAsUtf( '<td><a href="' + url_with_mode + '">' + obj_title + "</a></td>")
				else:
					if aPred == pc.property_information :
						WrtAsUtf( '<td colspan="2">' + obj_str + "</td>")
					else:
						WrtAsUtf( '<td>' + obj_str + "</td>")

				WrtAsUtf( "</tr>")

	WrtAsUtf( " </table>")

def Grph2Html( theCgi, topUrl, error_msg, isSubServer):
	"""
		This transforms an internal data graph into a HTML document.
	"""
	page_title = theCgi.m_page_title
	grph = theCgi.m_graph
	parameters = theCgi.m_parameters

	WrtHeader('text/html')
	WrtAsUtf( "<head>" )

	# TODO: Encode HTML special characters.
	WrtAsUtf( "<title>" + page_title + "</title>")

	WrtAsUtf( ' </head> <body>')

	WrtAsUtf("<br/>Script parameters<br/>")
	WriteParameters(parameters)

	# grph_scripts, grph_noscripts = SplitGrphOnScripts(grph)
	WrtAsUtf("<br/>Other urls related to this object<br/>")
	WriteOtherUrls()

	WrtAsUtf("<br/>Objects returned by this script<br/>")
	WriteAllObjects(error_msg,isSubServer,grph)

	WrtAsUtf("<br/>Related scripts<br/>")
	WriteScriptsTree(theCgi)

	WrtAsUtf( "</body> </html> ")

################################################################################
