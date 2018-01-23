
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
from lib_properties import pc
from lib_properties import MakeProp
import lib_exports
import lib_grammar

from lib_util import NodeLiteral
from lib_util import NodeUrl

import collections

# Functions for creating uris are imported in the global namespace.
from lib_uris import *
import lib_uris

################################################################################

def TimeStamp():
	return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())

################################################################################

nodeMachine = gUriGen.HostnameUri( lib_util.currentHostname )

################################################################################

# Could be reused if we want to focus on some processes only.
# proc in [ 'bash', 'gvim', 'konsole' ]
def UselessProc(proc):
	return False

################################################################################
	
## Also, the Apache 2.2 docs have a slightly different location for the registry key:
## HKEY_CLASSES_ROOT\.cgi\Shell\ExecCGI\Command\(Default) => C:\Perl\bin\perl.exe -wT

################################################################################

# TODO: Take the colors from the CSS html_exports.css
# TODO: Add a tool tip. Also, adapt the color to the context.
pattEdgeOrien = "\t%s -> %s [ color=%s, label=< <font point-size='10' " + \
	"color='#336633'>%s</font> > ] ;\n"
pattEdgeBiDir = "\t%s -> %s [ dir=both color=%s, label=< <font point-size='10' " + \
	"color='#336633'>%s</font> > ] ;\n"

################################################################################

def WriteDotHeader( page_title, layout_style, stream, grph ):
	# Title embedded in the page.
	stream.write('digraph "' + page_title + '" { \n')

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

# Returns a string for an URL which might be different from "entity.py" etc...
# TODO: Ca serait mieux de passer le texte avec la property.
def ExternalToTitle(extUrl):
	# Depending on where we come from, "%2F" instead of "/" ... ugly.
	# BEWARE: This is completely experimental. See if "Yawn" is actually used.
	if re.match( ".*/yawn/.*", extUrl ) or re.match( ".*%2Fyawn%2F.*", extUrl ):
		return "Yawn"

	pyNamMtch = re.match( ".*/([^.]+).py.*", extUrl )
	if pyNamMtch:
		pyNam = pyNamMtch.group(1)

		# After all, the script might be entity
		if pyNam == "entity":
			(objNam, entity_graphic_class, entity_id) = lib_naming.ParseEntityUri( extUrl )
			return objNam

		try:
			# TODO: See lib_naming.scripts_to_titles
			basNamToTxt = {
				"objtypes_wbem" : "Subtypes", # This key is duplicated !!!!
				"file_directory" : "Subdir",
				"file_to_mime" : "MIME",
				"objtypes_wmi" : "WMI tree",
				"objtypes_wbem" : "WBEM hier.",
				"class_type_all" : "Cross class",
				"dir_to_html" : "DIR"
			}
			return basNamToTxt[pyNam]
		except:
			return pyNam.replace("_"," ").capitalize()
	else:
		# sys.stderr.write("extUrl=%s\n"%extUrl)
		return "Literal:"+extUrl

# These properties must have their object displayed not as a separated node,
# but as a link displayed with a string, a plain HREF.
FlatPropertertiesList = [ pc.property_rdf_data_nolist1, pc.property_rdf_data_nolist2, pc.property_rdf_data_nolist3 ]
def IsFlatProperty(key):
	return key in FlatPropertertiesList

# Used for transforming into SVG format.
# If from entity.py, CollapsedProps = pc.property_directory,pc.property_script
def Rdf2Dot( grph, logfil, stream, CollapsedProperties ):
	fieldsSet = collections.defaultdict(list)

	# This maps RDFLIB nodes to DOT label names.
	dictRdf2Dot = {}

	# This returns the DOT label of a RDFLIB, and creates a new one if necessary.
	def RdfNodeToDotLabel(x):
		try:
			return dictRdf2Dot[x]
		except KeyError:
			nodelabel = "nd_%d" % len(dictRdf2Dot)
			dictRdf2Dot[x] = nodelabel
			return nodelabel

	# The QName is an abbreviation of URI reference with the namespace function for XML.
	# Edge label.
	# Transforms "http://primhillcomputers.com/ontologies/ppid" into "ppid"
	# TODO: Beware, a CGI parameter might be there. CGIPROP
	def qname(x, grph):
		try:
			q = grph.compute_qname(x)
			# q[0] is the shortened namespace "ns"
			# Could return q[0] + ":" + q[2]
			return q[2]
		except:
			return x
		# Nothing really interesting at the moment, just hardcodes.
		return lib_properties.prop_color(prop)

	# The input is any Python object.
	# This returns a simple object which can be transformed into a string.
	# If the input is a container, it returns a HTML table.
	def FormatElementAux(val,depth=0):
		if val is None:
			return ""

		try:
			int(val)
			return val
		except:
			pass

		try:
			float(val)
			return val
		except:
			pass

		if isinstance(val,dict):
			subTable = ""
			# TODO: Consider using six.iteritems.
			for subKey,subVal in val.items():
				subTd = FormatPair(subKey,subVal, depth + 1)
				if subTd:
					subTable += "<tr>%s</tr>" % subTd
			return "<table border='0'>%s</table>" % subTable

		# Note: Recursive list are not very visible.
		if isinstance(val, ( list, tuple ) ):
			# If this is an empty list or tuple.
			if not val:
				# return "(Empty)"
				# Empty set character in UTF8
				return "{"+"&#x2205;"+"}"
			if depth % 2 == 0:
				subTable = ""
				for subElement in val:
					subTd = FormatElement( subElement, depth + 1 )
					subTable += "<tr>%s</tr>" % subTd
				return "<table border='0'>%s</table>" % subTable
			else:
				subTable = ""
				for subElement in val:
					subTd = FormatElement( subElement, depth + 1 )
					subTable += subTd
				return "<table border='0'><tr>%s</tr></table>" % subTable

		try:
			decodVal = json.loads(val)
			return FormatElementAux(decodVal, depth + 1)

		except ValueError:
			# It is a string which cannot be converted to json.
			val = cgi.escape(val)
			return lib_exports.StrWithBr(val)
		except TypeError:
			# "Expected a string or buffer"
			# It is not a string, so it could be a datetime.datetime
			val = cgi.escape(str(val))
			return lib_exports.StrWithBr(val)
		return "FormatElement failure"

	def FormatElement(val,depth=0):
		if lib_kbase.IsLink(val):
			valTitle = "FormatElement "+ExternalToTitle(val)
			valTitleUL = lib_exports.DotUL(valTitle)
			return "<td align='left' balign='left' border='0' href='%s'>%s</td>" % (val,valTitleUL )

		resStr = FormatElementAux(val,depth)
		return "<td align='left' balign='left' border='0'>%s</td>" % resStr


	# Prints a key-value pair as two TD tags, to go in an HTML table.
	def FormatPair(key,val,depth=0):
		colFirst = "<td align='left' valign='top' border='0'>%s</td>" % lib_exports.DotBold(key)
		colSecond = FormatElement(val,depth+1)
		return colFirst + colSecond

	# Display in the DOT node the list of its literal properties.
	def FieldsToHtmlVertical(grph, the_fields):
		props = {} 
		idx = 0
		# TODO: The sort must put at first, some specific keys.
		# For example, sources_top/nmap_run.py, the port number as an int (Not a string)
		# Also, filenames, case-sensitive or not.
		for ( key, val ) in sorted(the_fields):
			# This should come first, but it does not so we prefix with "----". Hack !
			if key == pc.property_information:
				# Completely left-aligned. Col span is 2, approximate ratio.
				val = lib_exports.StrWithBr(val,2)
				currTd = "<td align='left' balign='left' colspan='2'>%s</td>" % val
			elif IsFlatProperty(key) :
				urlTxt = lib_naming.ParseEntityUri(val)[0]
				splitTxt = lib_exports.StrWithBr(urlTxt, 2)
				# The text of the link must be underlined.
				currTd = '<td href="%s" align="left" colspan="2">%s</td>' % ( val, lib_exports.DotUL(splitTxt) )
			else:
				key_qname = qname( key, grph )
				# This assumes: type(val) == 'rdflib.term.Literal'
				# sys.stderr.write("FORMAT ELEMENT: %s\n" %(dir(val)))
				if lib_kbase.IsLiteral(val):
					currTd = FormatPair( key_qname, val.value )
				else:
					currTd = FormatPair( key_qname, val )

			props[idx] = currTd
			idx += 1
		return props

	# Ca liste les labels des objects qui apparaissent dans les blocs,
	# et pointent vers le nom du record.
	dictCollapsedObjectLabelsToSubjectLabels = {}

	# This contains, for each node (subject), the related node (object) linked
	# to it with a property to be displayed in tables instead of individual nodes.
	dictPropsCollapsedSubjectsToObjectLists = {}

	for collapsPropObj in CollapsedProperties:
		collapsPropNam = lib_exports.PropToShortPropNam(collapsPropObj)
		dictPropsCollapsedSubjectsToObjectLists[collapsPropNam] = collections.defaultdict(list)


	# TODO: (TRANSLATE THIS) Une premiere passe pour batir l'arbre d'une certaine propriete.
	# Si pas un DAG, tant pis, ca fera un lien en plus.
	# ON voulait batir des records, mais les nodes dans un record ne peuvent pas
	# avoir un URL: Donc ca va pas evidemment.
	# HTML-LIKE Labels avec PORT et PORTPOS.
	# CA VA AUSSI SIMPLIFIER L'AFFICHAGE DES TRUCS ENORMES: Modules, Fichiers etc...
	# Et on pourra trier car il y a un ordre.
	# Donc ca doit etre facile d'ajouter des proprietes affichees comme ca.

	logfil.write( TimeStamp()+" Rdf2Dot: First pass\n" )

	# New intermediary node created.
	def CollapsedLabel(collapsPropNam,subjNam):
		return "R_" + collapsPropNam + "_" + subjNam

	# Called mainly from entity.py. If S points vers O, transforms "O" => "R_S:O"
	# Accordingly we create an edge: "S" => "R_S"
	def SubjNamFromCollapsed(collapsPropNam,subjNam):
		#sys.stderr.write("ADDING1 subjNam=%s collapsPropNam=%s\n" % (subjNam,collapsPropNam))
		collapsedSubjNam = dictCollapsedObjectLabelsToSubjectLabels[ subjNam ][collapsPropNam]
		#sys.stderr.write("ADDING2 subjNam=%s collapsPropNam=%s\n" % (subjNam,collapsPropNam))
		newSubjNam = CollapsedLabel( collapsPropNam, collapsedSubjNam ) + ":" + subjNam
		#sys.stderr.write("ADDED collapsedSubjNam=%s newSubjNam=%s collapsPropNam=%s\n" % (collapsedSubjNam,newSubjNam,collapsPropNam))
		return newSubjNam

	# This is sorted so the result is deterministic. Very small performance impact.
	# Any order will do as long as the result is always the same.
	sortedGrph = sorted(grph)

	# TODO: Loop only on the "collapsed" properties, the ones whose objects must be displayed
	# in tables, instead of links  - if only they have a single subject. Otherwise it cannot work.
	for subj, prop, obj in sortedGrph:

		# Objects linked with these properties, are listed in a table, instead of distinct nodes in a graph.
		if prop in CollapsedProperties:
			# TODO: We lose the property, unfortunately. Should make a map: subject => prop => object ?
			subjNam = RdfNodeToDotLabel(subj)

			propNam = lib_exports.PropToShortPropNam(prop)
			dictPropsCollapsedSubjectsToObjectLists[ propNam ][ subj ].append( obj )

			# Maybe we already entered it: Not a problem.
			objNam = RdfNodeToDotLabel(obj)

			# CollapsedProperties can contain only properties which define a tree,
			# as visibly the "object" nodes can have one ancestor only.
			try:
				# TODO: We should check if a node appears in two tables,
				# associated to two properties and/or two parent node.
				dictCollapsedObjectLabelsToSubjectLabels[ objNam ][ propNam ] = subjNam
			except KeyError:
				dictCollapsedObjectLabelsToSubjectLabels[ objNam ] = dict()
				dictCollapsedObjectLabelsToSubjectLabels[ objNam ][ propNam ] = subjNam

	# For getting the node of an object, as it might be in a table.
	def RdfNodeToDotLabelExtended(obj,prop):
		objNam = RdfNodeToDotLabel(obj)

		try:
			dictOfProps = dictCollapsedObjectLabelsToSubjectLabels[ objNam ]
		except KeyError:
			# sys.stderr.write("RdfNodeToDotLabelExtended propNam=%s objNam=%s\n"%(propNam,objNam) )
			return objNam

		# Let's hope there is only one collapsed property for this node. Otherwise, it means
		# that this node would be displayed in two different tables. It happened...
		if not prop is None:
			propNam = lib_exports.PropToShortPropNam(prop)
			try:
				# Maybe this property is not collapsed.
				subjNam = dictOfProps[propNam]
			except KeyError:
				prop = None

		# Maybe the property is not known, if the node is the subject.
		# Or the property is not collapsed.
		if prop is None:
			# In Python3, keys() is an iterable. No need to create a list.
			#propNam = list(dictOfProps.keys())[0]
			#propNam = dictOfProps.keys()[0]
			for propNam in dictOfProps.keys():
				break
			# First property available.
			subjNam = dictOfProps[propNam]

		newObjNam = CollapsedLabel( propNam, subjNam ) + ":" + objNam
		return newObjNam

	# Now we know that we have seen all nodes in a collapsed property.
	for subj, prop, obj in sortedGrph:
		if prop in CollapsedProperties:
			continue

		# Maybe the subject node belongs to a table, but the property is not known.
		subjNam = RdfNodeToDotLabelExtended(subj,None)
		if lib_kbase.IsLink(obj):

			prp_col = lib_properties.prop_color(prop)

			# TODO: GENERALIZE THIS TO ALL COMMUTATIVE PROPERTIES.
			# THAT IS: PROPERTIES WHOSE TRIPLES ARE MERGED WHEN
			# WE HAVE AT THE SAME TIME: (Subj,Prop,Obj) and (Obj,Prop,Subj).
			# WHEN THIS HAPPENS, THE ARROW MUST BE BIDIRECTIONAL.
			# TODO: All commutative relation have bidirectional arrows.
			# At the moment, only one property can be bidirectional.
			if prop == pc.property_socket_end:

				# BEWARE, MAYBE THIS IS A PORT INTO A TABLE. SO IT HAS TO BE PREFIXED BY THE RECORD NAME.
				objNam = RdfNodeToDotLabelExtended(obj,prop)
				if ( obj, prop, subj ) in grph :
					if subjNam < objNam:
						stream.write(pattEdgeBiDir % (subjNam, objNam, prp_col, qname(prop, grph)))
				else:
					# One connection only: We cannot see the other.
					stream.write(pattEdgeOrien % (subjNam, objNam, prp_col, qname(prop, grph)))
			elif prop in [ pc.property_rdf_data_nolist1 , pc.property_rdf_data_nolist2, pc.property_rdf_data_nolist3 ]:
				# TODO: Il suffit de tester si obj est un url de la forme "entity.py" ???
				# HTML and images urls can be "flattened" because the nodes have no descendants.
				# Do not create a node for this.
				# MIME links displayed in the same column as sub-directory.
				# Also, it might be enough to test if the object has the form "entity.py" because it has no descendant.
				# TODO: CGIPROP: Can it have several html or sub-rdf ?? It is necessary !
				fieldsSet[subj].append( ( prop, obj ) )
			else:
				objNam = RdfNodeToDotLabelExtended(obj,prop)
				# C est la que si subjNam est dans une liste de dictCollapsedSubjectsToObjectLists,
				# il faut rajouter devant, le nom du record, c est a dire SON subjNam + "_table_rdf_data:".
				try:
					# Syntax with colon required by DOT.
					propNam = lib_exports.PropToShortPropNam(prop)
					subjNam = SubjNamFromCollapsed(propNam,subjNam)
				except KeyError:
					# sys.stderr.write("PASS subjNam=%s objNam=%s\n"%(subjNam,objNam))
					pass

				stream.write(pattEdgeOrien % (subjNam, objNam, prp_col, qname(prop, grph)))
		elif obj == None:
			# No element created in nodes[]
			fieldsSet[subj].append((prop, "Null" ))
		else:
			# For Literals. No element created in nodes[]
			# Literals can be processed according to their type.
			# Some specific properties cannot have children so they can be stored as literals?
			# Les proprietes comme "pid", on devrait plutot afficher le lien vers le process, dans la table ???
			# Les URLs de certaines proprietes sont affichees en colonnes.
			# Ou bien pour ces proprietes, on recree un entity.py ??

			fieldsSet[subj].append( ( prop, obj ) )

	logfil.write( TimeStamp()+" Rdf2Dot: Replacing vectors: CollapsedProperties=%d.\n" % ( len( CollapsedProperties ) ) )

	# Now, replaces each vector by a single object containg a HTML table.
	# TODO: Unfortunately, the prop is lost, which implies that all children are mixed together.

	def ProcessCollapsedProperties( propNam ):
		dictCollapsedSubjectsToObjectLists = dictPropsCollapsedSubjectsToObjectLists[propNam]
		logfil.write( TimeStamp()+" Rdf2Dot: dictCollapsedSubjectsToObjectLists=%d.\n" % ( len( dictCollapsedSubjectsToObjectLists ) ) )

		for subjUrl, nodLst in lib_util.six_iteritems(dictCollapsedSubjectsToObjectLists):
			subjNam = RdfNodeToDotLabel(subjUrl)

			subjNamTab = CollapsedLabel(propNam,subjNam)
			try:
				# TODO: Cette logique ajoute parfois un niveau de noeud inutile. Plus exactement, ca duplique un noeud.
				# Ou plus exactement, le noed est represente par deux objects graphiques:
				# * Un qui a les scripts.
				# * Un autre qui a la liste HTML qu on fabrique.
				# => Peut-on imaginer de melanger les deux ??
				# Dans WritePatterns: Ajouter le nom du noeud au label.
				subjNam = SubjNamFromCollapsed(propNam,subjNam)
			except KeyError:
				pass

			# Point from the subject to the table containing the objects.
			stream.write(pattEdgeOrien % (subjNam, subjNamTab, "GREEN", propNam))

			( labText, subjEntityGraphicClass, entity_id) = lib_naming.ParseEntityUri( subjUrl )

			# Probleme avec les champs:
			# Faire une premiere passe et reperer les fields, detecter les noms des colonnes, leur attribuer ordre et indice.
			# Seconde passe pour batir les lignes.
			# Donc on ordonne toutes les colonnes.
			# Pour chaque field: les prendre dans le sens du header et quand il y a un trou, colonne vide.
			# Inutile de trier les field, mais il d'abord avoir une liste complete des champs, dans le bon sens.
			# CA SUPPOSE QUE DANS FIELDSSET LES KEYS SONT UNIQUES.
			# SI ON NE PEUT PAS, ALORS ON METTRA DES LISTES. MAIS CETTE CONTRAINTE SIMPLIFIE L'AFFICHAGE.

			# DOMMAGE QU ON SCANNE LES OBJETS DEUX FOIS UNIQUEMENT POUR AVOIR LES NOMS DES CHAMPS !!!!!!!!!!!!!
			# TODO: HEURISTIQUE: ON pourrait s'arreter aux dix premiers. Ou bien faire le tri avant ?
			# On bien prendre les colonnes de la premiere ligne, et recommencer si ca ne marche pas.
			# Unique columns of the descendant of this subject.
			rawFieldsKeys = set()
			for obj in nodLst:
				# One table per node.
				rawFieldsKeys.update( fld[0] for fld in fieldsSet[obj] )

			# sys.stderr.write("rawFieldsKeys BEFORE =%s\n" % str(rawFieldsKeys) )

			# Mandatory properties must come at the beginning of the columns of the header, with first indices.
			# BUG: Si on retire html de cette liste alors qu il y a des valeurs, colonnes absentes.
			# S il y a du html ou du RDF, on veut que ca vienne en premier.
			fieldsKeysOrdered = []
			for fldPriority in FlatPropertertiesList:
				try:
					# Must always be appended. BUT IF THERE IS NO html_data, IS IT WORTH ?
					# TODO: Remove if not HTML and no sub-rdf. CGIPROP

					# If the property is never used, exception then next property.
					rawFieldsKeys.remove( fldPriority )
					fieldsKeysOrdered.append( fldPriority )
				except KeyError:
					pass

			# This one is always removed because its content is concatenated at the first column.
			for fldToRemove in [ pc.property_information ]:
				try:
					rawFieldsKeys.remove( fldToRemove )
				except KeyError:
					pass

			# Appends rest of properties, sorted.
			fieldsKeys = fieldsKeysOrdered + sorted(rawFieldsKeys)

			# sys.stderr.write("fieldsKeys=%s\n" % str(fieldsKeys) )

			# This assumes that the header columns are sorted.
			keyIndices = { nameKey:indexKey for (indexKey,nameKey) in enumerate(fieldsKeys,1) }

			numberKeys = len(keyIndices)+1

			# Apparently, no embedded tables.
			dictHtmlLines = dict()
			for objUri in nodLst:
				# One table per node.
				subObjId = RdfNodeToDotLabel(objUri)

				# Beware "\L" which should not be replaced by "<TABLE>" but this is not the right place.
				subNodUri = objUri.replace('&','&amp;')

				try:
					(subObjNam, subEntityGraphicClass, subEntityId) = lib_naming.ParseEntityUriShort( objUri )
				except UnicodeEncodeError:
					sys.stderr.write( "UnicodeEncodeError error:%s\n" % ( objUri ) )
					(subObjNam, subEntityGraphicClass, subEntityId) = ("Utf problem1","Utf problem2","Utf problem3")

				# sys.stderr.write("subEntityGraphicClass=%s\n"%subEntityGraphicClass)

				# If this is a script, always displayed on white, even if reletd to a specific entity.
				# THIS IS REALLY A SHAME BECAUSE WE JUST NEED THE ORIGINAL PROPERTY.
				if objUri.find("entity.py") < 0:
					objColor = "#FFFFFF"
				else:
					objColor = lib_patterns.EntityClassToColor(subEntityGraphicClass)
				# This lighter cololor for the first column.
				objColorLight = lib_patterns.ColorLighter(objColor)

				# Some colors a bit clearer ? Or take the original color of the class ?
				td_bgcolor_plain = '<td BGCOLOR="%s" ' % objColor
				td_bgcolor_light = '<td BGCOLOR="%s" ' % objColorLight
				td_bgcolor = td_bgcolor_plain

				# Some columns might not have a value. The first column is for the key.
				columns = [ td_bgcolor + " ></td>" ] * numberKeys

				# Just used for the vertical order of lines, one line per object.
				title = ""

				# TODO: CGIPROP. This is not a dict, the same key can appear several times ?
				for ( key, val ) in fieldsSet[objUri]:
					if key == pc.property_information:
						# This can be a short string only.
						title += val
						continue

					# TODO: This is hard-coded.
					if IsFlatProperty(key) :

						# In fact, it might also be an internal URL with "entity.py"
						if lib_kbase.IsLiteral(val):
							if isinstance( val.value, (list, tuple )):
								strHtml = FormatElementAux(val.value)
								sys.stderr.write("val.value=%s\n"%strHtml)
								tmpCell = td_bgcolor + 'align="left">%s</td>' % strHtml
							else:
								tmpCell = td_bgcolor + 'align="left">%s</td>' % val.value
						else:
							valTitle = lib_naming.ParseEntityUri( val )[0]

							valTitleUL = lib_exports.DotUL(valTitle)
							tmpCell = td_bgcolor + 'href="%s" align="left" >%s</td>' % ( val , valTitleUL )

					else:
						try:
							float(val)
							tmpCell = td_bgcolor + 'align="right">%s</td>' % val
						except:
							# Wraps the string if too long. Can happen only with a literal.
							tmpCell = td_bgcolor + 'align="left">%s</td>' % lib_exports.StrWithBr(val)

					idxKey = keyIndices[key]
					columns[ idxKey ] = tmpCell

				if title:
					title_key = title
				else:
					title_key = subObjNam

				# Maybe the first column is a literal ?
				if subEntityId != "PLAINTEXTONLY":
					# WE SHOULD PROBABLY ESCAPE HERE TOO.
					columns[0] = td_bgcolor_light + 'port="%s" href="%s" align="LEFT" >%s</td>' % ( subObjId, subNodUri, title_key )
				else:
					subNodUri = cgi.escape(subNodUri)
					columns[0] = td_bgcolor_light + 'port="%s" align="LEFT" >%s</td>' % ( subObjId, subNodUri )

				# Several scripts might have the same help text, so add a number.
				# "Title" => "Title"
				# "Title" => "Title/2"
				# "Title" => "Title/3" etc...
				# Beware that it is quadratic with the number of scripts with identical info.
				title_idx = 2
				title_uniq = title_key
				while title_uniq in dictHtmlLines:
					title_uniq = "%s/%d" % ( title_key, title_idx )
					title_idx += 1

				# TODO: L'ordre est base sur les chaines mais devrait etre base sur le contenu. Exemple:
				# TODO: "(TUT_UnixProcess) Handle=10" vient avant "(TUT_UnixProcess) Handle=2"
				# TODO: title_uniq devrait etre plutot la liste des proprietes.
				# TODO: By clicking on the column names, we could change the order.
				dictHtmlLines[ title_uniq ] = "".join( columns )

			# Replace the first column by more useful information.
			numNodLst = len(nodLst)

			# TODO: Compute this once for all.
			eltNam = subEntityGraphicClass.split("/")[-1]
			if not eltNam:
				# TODO: This is not the right criteria. Must select if we are listing scripts.
				eltNam = "script"

			eltNamPlural = lib_grammar.ToPlural(eltNam,numNodLst)
			txtElements = "%d %s" % ( numNodLst, eltNamPlural )
			header = '<td border="1">' + lib_exports.DotBold(txtElements) + "</td>"

			# TODO: Replace each column name with a link which sorts the line based on this column.
			# The order of columns could be specified with an extra cgi argument with the columns names.
			for key in fieldsKeys:
				columnTitle = qname(key,grph)
				columnTitle = columnTitle.replace("_"," ").capitalize()
				header += "<td border='1'>" + lib_exports.DotBold( columnTitle ) + "</td>"
			# With an empty key, it comes first when sorting.
			dictHtmlLines[""] = header

			# MAYBE SHOULD BE DONE TWICE !!!!! SEE ALSO ELSEWHERE !!!!
			subjUrlClean = subjUrl.replace('&','&amp;')

			# ATTENTION: La forme du record est celle du sujet.
			# ca veut donc dire qu'on va avoir la meme couleur pour des objets de types
			# differents s'ils sont dans la meme relation avec un sujet identique ?
			numFields = len(fieldsKeys)+1

			# The label might be truncated
			if subjEntityGraphicClass:
				helpText = "List of " + subjEntityGraphicClass + " objects in " + labText
			else:
				helpText = "List of scripts in " + labText

			# TODO: Le title and the content are not necessarily of the same class.
			# labTextWithBr is the first line of the table containing nodes linked with the
			# same property. Unfortunately we have lost this property.
			labText = lib_exports.TruncateInSpace(labText,30)
			labTextWithBr = lib_exports.StrWithBr( labText )
			labTextWithBr += ": "+propNam

			if entity_id == "PLAINTEXTONLY":
				subjUrlClean = ""

			# This color is the table's contour.
			lib_patterns.WritePatterned( stream, subjEntityGraphicClass, subjNamTab, helpText, '"#000000"', subjUrlClean, numFields, labTextWithBr, dictHtmlLines )

			# TODO: Eviter les repetitions de la meme valeur dans une colonne en comparant d une ligne a l autre.
			# TODO: Si une cellule est identique jusqu a un delimiteur, idem, remplacer par '"'.

	if CollapsedProperties :
		for collapsedProp in CollapsedProperties:
			collapsedPropNam = lib_exports.PropToShortPropNam(collapsedProp)
			ProcessCollapsedProperties(collapsedPropNam)

	logfil.write( TimeStamp()+" Rdf2Dot: Display remaining nodes. dictRdf2Dot=%d\n" % len(dictRdf2Dot) )

	# Now, display the normal nodes, which are not displayed in tables.
	for objRdfNode, objLabel in lib_util.six_iteritems(dictRdf2Dot):
		# TODO: Avoids this lookup.
		if objLabel in dictCollapsedObjectLabelsToSubjectLabels :
			continue

		objPropsAsHtml = FieldsToHtmlVertical( grph, fieldsSet[objRdfNode])

		labHRef = objRdfNode.replace('&','&amp;')

		try:
			# TODO: Probleme ici: La chaine est deja codee pour HTML ce qui en rend le parsing different
			# TODO: ... de celui d'un URL deja decode. DOMMAGE: On quote puis unquote !!!
			(labText, objEntityGraphClass, entity_id) = lib_naming.ParseEntityUri( lib_util.urllib_unquote(objRdfNode) )
		except UnicodeEncodeError:
			sys.stderr.write( "UnicodeEncodeError error:%s\n" % ( objRdfNode ) )

		# WritePatterned receives an list of strings similar to "<td>jhh</td><td>jhh</td><td>jhh</td>"
		# This function adds <tr> and </tr> on both sides.
		# This avoids concatenations.

		# Ampersand are intentionnally doubled, because later on they are replaced twice.
		# That is, interpreted twice as HTML entities.
		# This might be temporary until we replace CGI arguments by genuine WMI Monikers.
		labTextNoAmp = labText.replace("&amp;amp;"," ")
		labTextNoAmp = labTextNoAmp.strip()
		labTextClean = lib_exports.StrWithBr( labTextNoAmp)
		# Two columns because it encompasses the key and the value.

		if objEntityGraphClass:
			helpText = labTextNoAmp + " is a " + objEntityGraphClass
		else:
			if labTextClean.startswith("http"):
				helpText = "External URL " + labTextNoAmp
			else:
				helpText = "Script " + labTextNoAmp

		# This color is the object's contour.
		lib_patterns.WritePatterned( stream, objEntityGraphClass, objLabel, helpText, '"#000000"', labHRef, 2, labTextClean, objPropsAsHtml )

	logfil.write( TimeStamp()+" Rdf2Dot: Leaving\n" )
	stream.write("}\n")

################################################################################

# Copies a file to standard output.
def CopyToOut(logfil,svg_out_filnam,out_dest):
	logfil.write( TimeStamp() + " Output without conversion: %s\n" % svg_out_filnam  )
	infil = open(svg_out_filnam,'rb')
	strInRead = infil.read()
	nbOut = out_dest.write( strInRead )
	logfil.write( TimeStamp() + " End of output without conversion: %s chars\n" % str(nbOut) )
	infil.close()

################################################################################

# TODO: Consider using the Python module pygraphviz: Small speedup probably.
# But the priority is to avoid graphes which are too long to route.
# TODO: Consider using the Python module pydot,
# but anyway it needs to have graphviz already installed.
# Also, creating an intermediary files helps debugging.
def Dot2Svg(dot_filnam_after,logfil, viztype, out_dest ):
	sys.stderr.write("viztype=%s\n"%(viztype) )
	tmpSvgFil = TmpFile("Dot2Svg","svg")
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
	msg = "svg_command=" + " ".join(svg_command) + "\n"
	sys.stderr.write(msg)
	logfil.write(TimeStamp()+" "+msg)

	ret = subprocess.call( svg_command, stdout=logfil, stderr=logfil, shell=False )
	logfil.write(TimeStamp()+" Process ret=%d\n" % ret)

	if not os.path.isfile( svg_out_filnam ):
		ErrorMessageHtml("SVG file " + svg_out_filnam + " could not be created." )
	
	# If there is an error, we should write it as an HTML page.
	# On the other hand it will be impossible to pipe the output
	# because it would assume a SVG document.
	# TODO: See that later.

	# For the specific case when it writes into a socket. Strange behaviour:
	# Without this, it wraps our SVG code in HTML tags, adds its own HTTP header, etc...
	# The test on stdout comes at the end because it does not work on old Python versions.
	if lib_util.isPlatformWindows and sys.version_info >= (3,4,) and out_dest != sys.stdout.buffer :
		logfil.write( TimeStamp() + " SVG Header removed\n" )
	else:
		logfil.write( TimeStamp() + " Writing SVG header\n" )
		lib_util.WrtHeader( "image/svg+xml" )

	# Here, we are sure that the output file is closed.
	CopyToOut(logfil,svg_out_filnam,out_dest)

################################################################################

def Grph2Svg( page_title, error_msg, isSubServer, parameters, grph, parameterized_links, topUrl, dot_style ):
	tmpLogFil = TmpFile("Grph2Svg","log")
	try:
		logfil = open(tmpLogFil.Name,"w")
	except:
		exc = sys.exc_info()[1]
		sys.stderr.write("Grph2Svg caught %s when opening:%s\n"%(str(exc),tmpLogFil.Name))
		ErrorMessageHtml("Grph2Svg caught %s when opening:%s\n"%(str(exc),tmpLogFil.Name))

	logfil.write( "Starting logging\n" )

	tmpDotFil = TmpFile("Grph2Dot","dot")
	dot_filnam_after = tmpDotFil.Name
	rdfoutfil = open( dot_filnam_after, "w" )
	logfil.write( TimeStamp()+" Created "+dot_filnam_after+"\n" )

	dot_layout = WriteDotHeader( page_title, dot_style['layout_style'], rdfoutfil, grph )
	lib_exports.WriteDotLegend( page_title, topUrl, error_msg, isSubServer, parameters, parameterized_links, rdfoutfil, grph )
	logfil.write( TimeStamp()+" Legend written\n" )
	Rdf2Dot( grph, logfil, rdfoutfil, dot_style['collapsed_properties'] )
	logfil.write( TimeStamp()+" About to close dot file\n" )

	# BEWARE: Do this because the file is about to be reopened from another process.
	rdfoutfil.flush()
	os.fsync( rdfoutfil.fileno() )
	rdfoutfil.close()

	out_dest = lib_util.DfltOutDest()

	Dot2Svg( dot_filnam_after, logfil, dot_layout, out_dest )
	logfil.write( TimeStamp()+" closing log file\n" )
	logfil.close()

################################################################################

# The result can be sent to the Web browser in several formats.
# TODO: The nodes should be displayed always in the same order.
# THIS IS NOT THE CASE IN HTML AND SVG !!
# def OutCgiMode( grph, topUrl, mode, pageTitle, dotLayout, errorMsg = None, isSubServer=False, parameters = dict()):
def OutCgiMode( theCgi, topUrl, mode, errorMsg = None, isSubServer=False ):
	grph = theCgi.m_graph
	pageTitle = theCgi.m_page_title
	dotLayout = theCgi.m_layoutParams
	parameters = theCgi.m_parameters
	parameterized_links = theCgi.m_parameterized_links

	if mode == "html":
		# Used rarely and performance not very important.
		import lib_export_html
		lib_export_html.Grph2Html( theCgi, topUrl, errorMsg, isSubServer, globalCgiEnvList)
	elif mode == "json":
		lib_exports.Grph2Json( pageTitle, errorMsg, isSubServer, parameters, grph)
	elif mode == "menu":
		lib_exports.Grph2Menu( pageTitle, errorMsg, isSubServer, parameters, grph)
	elif mode == "rdf":
		lib_exports.Grph2Rdf( grph)
	else: # Or mode = "svg"
		# Default value, because graphviz did not like several CGI arguments in a SVG document (Bug ?).
		Grph2Svg( pageTitle, errorMsg, isSubServer, parameters, grph, parameterized_links, topUrl, dotLayout )

################################################################################

def MakeDotLayout(dot_layout, collapsed_properties ):
	return { 'layout_style': dot_layout, 'collapsed_properties':collapsed_properties }

################################################################################

def GetCallingModuleDoc():
	"""
		Works if called from Apache, cgiserver.py or wsgiserver.py
		This is a global and can be fetched differently, if needed.
		It returns the whole content.
	"""

	sys.stderr.write("GetCallingModuleDoc Main module:%s\n"% str(sys.modules['__main__']))

	# If it uses an unique CGI script.
	if lib_util.modeOVH or globalMergeMode:
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

			# Even more hacky, just for OVH hosting.
			if lib_util.modeOVH:
				# Then it starts again with "survol."
				filnamCaller = filnamCaller[ len(modulePrefix): ]
			sys.stderr.write("GetCallingModuleDoc filnamCaller=%s\n" % filnamCaller)
			try:
				moduleCaller = sys.modules[filnamCaller]
			except:
				return filnamCaller + ":No doc"

			theDoc = moduleCaller.__doc__.strip()
			sys.stderr.write("GetCallingModuleDoc  moduleCaller.__doc__=%s\n" % theDoc)
			return theDoc
		except:
			exc = sys.exc_info()[1]
			sys.stderr.write("GetCallingModuleDoc Caught when getting doc:%s\n"%str(exc))
			return "Caught when getting doc:"+str(exc)
	else:
		try:
			# This does not work when in WSGI mode, nor when merging.
			mainModu = sys.modules['__main__']
			sys.stderr.write("GetCallingModuleDoc Main module:%s\n"% mainModu.__name__ )
			page_title = mainModu.__doc__
			if page_title:
				page_title = page_title.strip()
				return page_title
			else:
				return "No doc"
		except:
			exc = sys.exc_info()[1]
			return "GetCallingModuleDoc (Caught %s)" % str(exc)


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
	layoutParams = { 'layout_style': "", 'collapsed_properties':[] }
	cgiParams = {}
	cgiParamLinks = {}
	for theCgiEnv in globalCgiEnvList:
		# theCgiEnv.m_page_title contains just the first line.
		(page_title_first,page_title_rest) = lib_util.SplitTextTitleRest(theCgiEnv.m_page_title)
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
			sys.stderr.write("Error:%s Parameters:%s\n"%(errorMsg,str(theCgiEnv.m_parameters)))

	# Eliminate duplicates in the list of collapsed properties.
	myList = layoutParams['collapsed_properties']
	mySet = set(myList)
	layoutParams['collapsed_properties'] = list(mySet)

	topUrl = lib_util.TopUrl( "", "" )

	#class CgiInterface(object):
	#	pass

	# pseudoCgi = CgiInterface()

	pseudoCgi = CgiEnv()
	pseudoCgi.m_graph = globalGraph
	pseudoCgi.m_page_title = page_title
	pseudoCgi.m_layoutParams = layoutParams
	# Not sure this is the best value, but this is usually done.
	# TODO: We should have a plain map for all m_arguments occurences.
	pseudoCgi.m_arguments = cgi.FieldStorage()
	pseudoCgi.m_parameters = cgiParams
	pseudoCgi.m_parameterized_links = cgiParamLinks
	pseudoCgi.m_entity_type = ""
	pseudoCgi.m_entity_id = ""
	pseudoCgi.m_entity_host = ""

	# It also needs this method:
	# def GetParameters(self,paramkey):

	OutCgiMode( pseudoCgi, topUrl, theMode, errorMsg = cumulatedError )

	return

################################################################################

class CgiEnv():
	"""
		This class parses the CGI environment variables which define an entity.
	"""
	def __init__(self, parameters = {}, can_process_remote = False ):
		# TODO: This value is read again in OutCgiRdf, we could save time by making this object global.
		sys.stderr.write( "CgiEnv parameters=%s\n" % ( str(parameters) ) )

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

		docModuAll = GetCallingModuleDoc()

		# Take only the first non-empty line. See lib_util.FromModuleToDoc()
		docModuSplit = docModuAll.split("\n")
		self.m_page_title = docModuSplit[0]

		# Title page contains __doc__ plus object label.
		callingUrl = lib_util.RequestUri()
		self.m_calling_url = callingUrl
		sys.stderr.write("CgiEnv m_page_title=%s m_calling_url=%s\n"%(self.m_page_title,self.m_calling_url))
		parsedEntityUri = lib_naming.ParseEntityUri(callingUrl,longDisplay=False)
		if parsedEntityUri[2]:
			# If there is an object to display.
			# Practically, we are in the script "entity.py" and the single doc string is "Overview"
			fullTitle = parsedEntityUri[0]
			self.m_page_title += " " + fullTitle

			# We assume there is an object, and therefore a class and its description.
			entity_class = parsedEntityUri[1]

			# Similar code in objtypes.py
			entity_module = lib_util.GetEntityModule(entity_class)
			entDoc = entity_module.__doc__
			# The convention is the first line treated as a title.
			if entDoc:
				self.m_page_title += "\n" + entDoc

		# If we can talk to a remote host to get the desired values.

		# Global CanProcessRemote has precedence over parameter can_process_remote
		# whcih should probably be deprecated, although they do not have exactly the same role:
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
		sys.stderr.write("CgiEnv m_entity_type=%s m_entity_id=%s m_entity_host=%s\n"%(self.m_entity_type,self.m_entity_id,self.m_entity_host))
		self.m_entity_id_dict = lib_util.SplitMoniker(self.m_entity_id)

		# Depending on the caller module, maybe the arguments should be 64decoded. See "sql/query".
		# As the entity type is available, it is possible to import it and check if it encodes it arguments.
		# See presence of source_types.sql.query.DecodeCgiArg(keyWord,cgiArg) for example.

		# This is probably too generous to indicate a local host.
		self.TestRemoteIfPossible(can_process_remote)

		# TODO: HOW WILL WE RESTORE THE ORIGINAL DISPLAY MODE ?
		if mode == "edit":
			self.EditionMode()

	def TestRemoteIfPossible(self,can_process_remote):
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
			xid = self.m_arguments["xid"].value
		except KeyError:
			# See function EditionMode
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
	def EditionMode(self):
		"""This allow to edit the CGI parameters when in SVG (Graphviz) mode"""
		import lib_export_html
		import lib_edition_parameters

		formAction = os.environ['SCRIPT_NAME']
		sys.stderr.write("EditionMode formAction=%s\n"%formAction)

		# It uses the same CSS as in HTML mode.
		lib_export_html.DisplayHtmlTextHeader(self.m_page_title+" - parameters")

		print("<body>")

		print("<h3>%s</h3><br>"%self.m_page_title)

		lib_edition_parameters.FormEditionParameters(formAction,self)

		print("</body>")
		print("</html>")
		sys.exit(0)

	# These are the parameters specific to the script, which are edit in our HTML form, in EditionMode().
	# They must have a default value. Maybe we could always have an edition mode when their value
	# is not set.
	# If the parameter is "cimom", it will extract the host of Uris like these: Wee GetHost()
	# https://jdd:test@acme.com:5959/cimv2:CIM_RegisteredProfile.InstanceID="acme:1"

	def GetParameters(self,paramkey):
		sys.stderr.write("GetParameters paramkey='%s' m_arguments=%s\n" % (paramkey,str(self.m_arguments) ) )

		# Default value if no CGI argument.
		try:
			dfltValue = self.m_parameters[paramkey]
			# sys.stderr.write("GetParameters %s Default=%s\n" % ( paramkey, dfltValue ) )
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
			sys.stderr.write("GetParameters paramkey='%s' paramVal='%s' as CGI\n" % ( paramkey, paramVal ) )
		except KeyError:
			sys.stderr.write("GetParameters paramkey='%s' not as CGI\n" % ( paramkey ) )
			hasArgValue = False

		# Now converts it to the type of the default value. Otherwise untouched.
		if hasDfltVal:
			if hasArgValue:
				paramTyp = type(dfltValue)
				paramVal = paramTyp( paramVal )
				sys.stderr.write("GetParameters paramkey='%s' paramVal='%s' after conversion to %s\n" % ( paramkey, paramVal, str(paramTyp) ) )
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
					sys.stderr.write("GetParameters paramkey='%s' set to FALSE\n" % ( paramkey ) )
				except KeyError:
					paramVal = dfltValue
					sys.stderr.write("GetParameters paramkey='%s' set to paramVal='%s'\n" % ( paramkey, paramVal ) )
		else:
			if not hasArgValue:
				sys.stderr.write("GetParameters no value nor default for paramkey='%s' m_parameters=%s\n" % ( paramkey, str(self.m_parameters)))
				# lib_util.InfoMessageHtml("GetParameters no value nor default for %s\n" % paramkey )
				paramVal = ""
			else:
				sys.stderr.write("GetParameters nothing for paramkey='%s'\n" % ( paramkey ))

		# TODO: Beware, empty strings are NOT send by the HTML form,
		# TODO: so an empty string must be equal to the default value.

		return paramVal

	# This is used for compatibility with the legacy scripts, which has a single id.
	# Now all parameters must have a key. As a transition, GetId() will return the value of
	# the value of an unique key-value pair.
	# If this class is not in DMTF, we might need some sort of data dictionary.
	def GetId(self):
		sys.stderr.write("GetId m_entity_type=%s m_entity_id=%s\n" % ( self.m_entity_type, str( self.m_entity_id ) ) )
		try:
			# If this is a top-level url, no object type, therefore no id.
			if self.m_entity_type == "":
				return ""

			splitKV = lib_util.SplitMoniker(self.m_entity_id)
			sys.stderr.write("GetId splitKV=%s\n" % ( str( splitKV ) ) )

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
		self.EditionMode()
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
	def GetNamespaceType(self):
		return lib_util.ParseNamespaceType( self.m_entity_type )

	# When in merge mode, these parameters must be aggregated, and used only during
	# the unique generation of graphic data.
	def OutCgiRdf(self, dot_layout = "", collapsed_properties=[] ):
		global globalCgiEnvList
		sys.stderr.write("OutCgiRdf globalMergeMode=%d len(globalCgiEnvList)=%d\n"%(globalMergeMode,len(globalCgiEnvList)))
		sys.stderr.write("OutCgiRdf m_calling_url=%s m_page_title=%s\n"%(self.m_calling_url,self.m_page_title))

		self.m_layoutParams = MakeDotLayout( dot_layout, collapsed_properties )

		mode = lib_util.GuessDisplayMode()

		topUrl = lib_util.TopUrl( self.m_entity_type, self.m_entity_id )

		if self.m_page_title is None:
			self.m_page_title = "PAGE TITLE SHOULD BE SET"

		if globalMergeMode:
			# At the end, only one call to OutCgiMode() will be made.
			globalCgiEnvList.append(self)
		else:
			OutCgiMode( self, topUrl, mode )

	# Example: cgiEnv.AddParameterizedLinks( "Next", { paramkeyStartIndex : startIndex + maxInstances } )
	def AddParameterizedLinks( self, urlLabel, paramsMap ):
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
			# sys.stderr.write("AddParameterizedLinks argK=%s argV=%s\n"%(argK,argV))
			prmsCopy[argK] = lib_util.urllib_quote(argV)

		# Update these parameters with the values specific for this label.
		for paramKey in paramsMap:
			# Check that it is a valid parameter.
			try:
				self.m_parameters[paramKey]
			except KeyError:
				ErrorMessageHrml("Parameter %s should be defined for a link"%paramKey)
			prmsCopy[paramKey] = paramsMap[paramKey]

		sys.stderr.write("prmsCopy=%s\n"%str(prmsCopy))

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

		sys.stderr.write("labelledUrl=%s\n"%labelledUrl)


		self.m_parameterized_links[urlLabel] = labelledUrl


################################################################################

globalErrorMessageEnabled = True

# Used when merging several scripts, otherwise there is no way to find
# which scripts produced an error.
def ErrorMessageEnable(flag):
	global globalErrorMessageEnabled
	globalErrorMessageEnabled = flag

def ErrorMessageHtml(message):
	sys.stderr.write("ErrorMessageHtml globalErrorMessageEnabled=%d\n"%globalErrorMessageEnabled)

	if globalErrorMessageEnabled:
		# If we are in Json mode, this returns a special json document with the error message.
		try:
			qry = os.environ["QUERY_STRING"]
			isJson = qry.endswith("mode=json")
			if isJson:
				lib_exports.WriteJsonError(message)
				sys.exit(0)
			
		except KeyError:
			pass

		sys.stderr.write("ErrorMessageHtml ENABLED globalErrorMessageEnabled=%d\n"%globalErrorMessageEnabled)
		lib_util.InfoMessageHtml(message)
		# TODO: Fix with wsgi which just displays "A server error occurred.  Please contact the administrator."
		sys.exit(0)
	else:
		# Instead of exiting, it throws an exception which can be used by merge_scripts.py
		sys.stderr.write("ErrorMessageHtml DISABLED globalErrorMessageEnabled=%d\n"%globalErrorMessageEnabled)
		# It might be displayed in a HTML document.
		messageClean = cgi.escape(message)
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
	# For doxygen, we should need shell=True but this is NOT safe.
	ret = subprocess.call(command, stdout=sys.stderr, stderr=sys.stderr, shell=False)
	return ret

################################################################################

def TryDir(dir):
	if( os.path.isdir(dir) ):
		return dir
	raise Exception("Not a dir:"+dir)

# The temp directory as specified by the operating system.
def TmpDir():
	try:
		# Maybe these environment variables are undefined for Apache user.
		return TryDir( os.environ["TEMP"].replace('\\','/') )
	except Exception:
		pass

	try:
		return TryDir( os.environ["TMP"].replace('\\','/') )
	except Exception:
		pass

	if lib_util.isPlatformWindows:
		try:
			return TryDir( os.environ["USERPROFILE"].replace('\\','/') + "/AppData/Local/Temp" )
		except Exception:
			pass

		try:
			return TryDir( "C:/Windows/Temp" )
		except Exception:
			pass

		return TryDir( "C:/Temp" )
	else:
		return TryDir( "/tmp" )

# This will not change during a process.
tmpDir = TmpDir()
		
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
		sys.stderr.write("tmp=%s cwd=%s\n" % ( self.Name, os.getcwd() ) )

	def DbgDelFil(self,filNam):
		if True:
			sys.stderr.write("Deleting="+filNam+"\n")
			os.remove(filNam)
		else:
			sys.stderr.write("NOT Deleting="+filNam+"\n")

	def __del__(self):
		try:
			if self.Name:
				self.DbgDelFil(self.Name)

			if self.TmpDirToDel not in [None,"/",""]:
				sys.stderr.write("About to NOT del %s\n" % self.TmpDirToDel )
				for root, dirs, files in os.walk(self.TmpDirToDel, topdown=False):
					for name in files:
						self.DbgDelFil(os.path.join(root, name))
					for name in dirs:
						#os.rmdir(os.path.join(root, name))
						pass

		except Exception:
			exc = sys.exc_info()[1]
			sys.stderr.write("__del__.Caught: %s. TmpDirToDel=%s Name=%s\n" % ( str(exc), str(self.TmpDirToDel), str(self.Name) ) )
		return


################################################################################

def IsSharedLib(path):

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
# So by default we do not display them.
def IsFontsFile(path):

	if lib_util.isPlatformWindows:
		tmp, fileExt = os.path.splitext(path)
		# sys.stderr.write("IsFontsFile fileExt=%s\n" % fileExt)
		return fileExt in [ ".ttf", ".ttc" ]

	elif lib_util.isPlatformLinux:
		for start in [ '/usr/share/locale/', '/usr/share/fonts/', '/etc/locale/', '/var/cache/fontconfig/', '/usr/lib/jvm/' ] :
			if path.startswith( start ):
				return True

	return False

# Used when displaying all files open by a process: There are many of them,
# so the useless junk could maybe be eliminated.
# Or rather make it an option.
def MeaninglessFile(path, removeSharedLibs, removeFontsFile ):
	if removeSharedLibs:
		if IsSharedLib(path):
			return True

	if removeFontsFile:
		if IsFontsFile(path):
			# sys.stderr.write("YES MeaninglessFile path=%s\n" % path)
			return True

	return False


################################################################################
def KillProc(pid):
	sys.stderr.write("About to kill pid=" + str(pid) )
	try:
		# SIGQUIT apparently not defined on Windows.
		if lib_util.isPlatformLinux:
			os.kill( pid, signal.SIGQUIT )
		else:
			# On Linux, it raises: KeyboardInterrupt
			os.kill( pid, signal.SIGINT )

	except AttributeError:
		exc = sys.exc_info()[1]
		# 'module' object has no attribute 'SIGQUIT'
		sys.stderr.write("Caught:"+str(exc)+" when killing pid=" + str(pid) )
	except Exception:
		# For example: [Errno 3] No such process.
		exc = sys.exc_info()[1]
		sys.stderr.write("Unknown exception " + str(exc) + " when killing pid=" + str(pid) )

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
def FormatUser(usrnam):
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

