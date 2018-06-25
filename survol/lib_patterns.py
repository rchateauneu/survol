# RGB colors here: http://www.pagetutor.com/common/bgcolors216.html

import sys
import lib_util

# We could also use dot record nodes.
# On the other hand, it is convenient to have some control on the final SVG code.

#                                                shape        colorfill  colorbg    border is_rounded
dictGraphParams = {
	"addr"                                   : ( "rarrow",    "#FFFF99", "#FFFF99", 0, False ),
	"CIM_Process"                            : ( "component", "#99FF88", "#99FF88", 0, False ),
	"CIM_Directory"                          : ( "folder",    "#8899FF", "#8899FF", 0, False ),
	"CIM_DataFile"                           : ( "note",      "#88BBFF", "#88BBFF", 0, False ),
	"group"                                  : ( "plain",     "#88BBFF", "#88BBFF", 0, False ),
	"CIM_ComputerSystem"                     : ( "signature", "#CCFFCC", "#CCFFCC", 0, False ),
	"memmap"                                 : ( "tab",       "#CCFFCC", "#CCFFCC", 0, False ),
	"CIM_LogicalDisk"                        : ( "box3d",     "#FFCCFF", "#FFCC66", 0, False ),
	"smbfile"                                : ( "tab",       "#99CCFF", "#FFCC66", 0, True ),
	"smbserver"                              : ( "tab",       "#99CCFF", "#FFCC66", 0, True ),
	"smbshr"                                 : ( "tab",       "#99CCFF", "#FFCC66", 0, True ),
	"linker_symbol"                          : ( "none",      "#99FFCC", "#FFCC66", 0, False ),
	"user"                                   : ( "octagon",   "#EEAAAA", "#FFCC66", 0, False ),
	"Win32_Service"                          : ( "component", "#EEAAAA", "#FFCC66", 0, False ),
	"Win32_UserAccount"                      : ( "octagon",   "#EEAAAA", "#FFCC66", 0, True ),
}

dfltGraphParams =                              ( "none",      "#FFFFFF", "#99BB88", 1, False )

# shape        colorfill  colorbg    border is_rounded
# On imagine une fonction par attribut et par module, sous-module etc...
# sqlite.shape() qui est supersedee par sqlite.table.shape() etc ...
# Meme chose pour les attributs shape(), colorfill(), colorbg(), border is_rounded
# On part du nivdeau le plus bas et on remonte jusqu'a trouver la fonction.
# On met tout dans un cache evidemment.
# On generalise la logique pour pouvoir l'appliquer a tous les attributs.

# This color is used to generate HTML code in DOT.
def EntityClassToColor(subEntityGraphicClass):
	if subEntityGraphicClass:
		arrAttrs = TypeToGraphParams(subEntityGraphicClass)
		bgCol = arrAttrs[1]
		return bgCol
	else:
		# If this is a script.
		return "#FFFFFF"


def ColorLighter(objColor):
	def ColorLighterNocache(objColor):
		def Lighter(X):
			dec = int(X,16)
			if dec < 13:
				dec +=2
			elif dec == 14:
				dec = 15
			return "0123456789ABCDEF"[dec]

		objColorLight = "#" + Lighter(objColor[1]) + objColor[2] + Lighter(objColor[3]) + objColor[4]  + Lighter(objColor[5]) + objColor[6]
		return objColorLight

	try:
		return ColorLighter.CacheMap[objColor]
	except KeyError:
		lig = ColorLighterNocache(objColor)
		ColorLighter.CacheMap[objColor] = lig
		return lig

ColorLighter.CacheMap = dict()


# Returns graphic parameters given a type without namespace.
# For example "Win32_Service", "oracle/package"
# TODO: Should use lib_util.HierarchicalFunctionSearch
def TypeToGraphParams(typeWithoutNS):
	# sys.stderr.write("lib_patterns.TypeToGraphParams typeWithoutNS=%s keys=%s\n"%(typeWithoutNS,str(dictGraphParams.keys())))

	# Safety check.
	if typeWithoutNS.find(".") >= 0:
		raise "Invalid typeWithoutNS=%s" % typeWithoutNS

	typeWithoutNS = typeWithoutNS.replace("/",".")

	# Fastest access from the cache.
	try:
		return dictGraphParams[typeWithoutNS]
	except KeyError:
		vecGraph = TypeToGraphParamsNoCache(typeWithoutNS)
		dictGraphParams[typeWithoutNS] = vecGraph
	return vecGraph

# Gets the graphic attributes: Each of them comes form the module of the entity or an upper module.
# TODO: At the moment, we cannot distinguish between our entites (Defined in our modules) and
# CIM properties which can only be stored but elsewhere. But CIM classes have no graphic attributes.

# Pour tous les attributs graphiques, ce serait mieux d'avoir des CSS avec le nom de la classe
# qui seraient charges automatiquement a partir de D3 et convertis a la volee pour Graphviz.
#
# Certes Grphviz n accepte pas CSS: http://stackoverflow.com/questions/31807719/using-css-classes-in-html-labels-on-graphviz
# Mais on peut extraire certains attributs a la volee.
#
# Donc:
# (1) Pour le graphisme aller chercher en premier un XXX.css dans le directory de la classe,
# a cote du __init__.py, et generer les attributs dont on a besoin.
# (2) Si ya pas de CSS ou bien si des attributs manquent, aller chercher les fonctions dans le module,
# comme maintenant.
def TypeToGraphParamsNoCache(typeWithoutNS):

	vecGraphFunctions = [
		"Graphic_shape","Graphic_colorfill","Graphic_colorbg","Graphic_border","Graphic_is_rounded"
	]

	vecProps = []
	for idxGrph in range(len(vecGraphFunctions)):
		gFuncName = vecGraphFunctions[idxGrph]
		grphFunc = lib_util.HierarchicalFunctionSearchNoCache(typeWithoutNS,gFuncName)

		if grphFunc:
			grphVal = grphFunc()
		else:
			# If no such function defined for this module and its ancestors.
			grphVal = dfltGraphParams[idxGrph]
		vecProps.append( grphVal )

	return vecProps


# This returns an array of format strings which are used to generate HTML code.
def BuildPatternNode(tp):
	shape  = tp[0]
	colorfill  = tp[1]
	colorbg  = tp[2]
	border = tp[3]
	is_rounded = tp[4]

	# TODO: La premiere ligne est moche. Celle par defaut est mieux remplie.
	if is_rounded:
		style = 'style="rounded,filled"'
	else:
		style = 'style="filled"'

	# First element if this is a URI, second element if plain string.
	fmtWithUri = '%s [ shape=' + shape + ', tooltip="%s", ' + style + ' fillcolor="' + colorfill + '" color=%s label=< <table color="' + '#000000' + '"' + \
		" cellborder='0' cellspacing='0' border='" + str(border) + "'><tr>" + \
		'<td href="%s" bgcolor="' + colorbg + '" colspan="%d">%s</td>' + \
		"</tr>"

	fmtWithNoUri = '%s [ shape=' + shape + ', tooltip="%s", ' + style + ' fillcolor="' + colorfill + '" color=%s label=< <table color="' + '#000000' + '"' + \
		" cellborder='0' cellspacing='0' border='" + str(border) + "'><tr>" + \
		'<td bgcolor="' + colorbg + '" colspan="%d">%s</td>' + \
		"</tr>"

	return [fmtWithUri,fmtWithNoUri]

# TODO: We could avoid one stage of cache. But this add extra flexibility
# if there are more parameters than only the class.
dictTypeToPatterns = {}

# Returns a HTML pattern given an entity type. Similar to TypeToGraphParams()
# but it removes the namespace if there is one.
def PatternNode(typeFull):
	# TODO: Three possible syntaxes for the type:
	# "root\CIMV2:CIM_AssociatedMemory" : WMI class     => Investigate base classes.
	# "root/CIMV2:CIM_AssociatedMemory" : WBEM class    => Investigate base classes.
	# "CIM_Process" or "oracle/table"   : Custom class  => Split.
	# We would need some sort of inheritance chains.
	try:
		return dictTypeToPatterns[typeFull]
	except KeyError:
		# This removes the WBEM or WMI namespace.
		type = typeFull.split(":")[-1]
		arrayGraphParams = TypeToGraphParams(type)
		pattArray = BuildPatternNode(arrayGraphParams)
		dictTypeToPatterns[typeFull] = pattArray
		return pattArray

def WritePatterned( stream, aType, subjNamTab, helpText, color, labHRef, numFields, labText, dictLines ):
	pattArray = PatternNode(aType)

	# TODO: The title and the elements might not have the same color.

	# TODO: At least, < and > in labels are correctly displayed, but not really clickable.
	# The best is to avoid them in entities names and urls.
	labText = helpText.replace("<","&lt;").replace(">","&gt;")
	labHRef = labHRef.replace("<","&lt;").replace(">","&gt;")

	try:
		if labHRef:
			stream.write( pattArray[0] % ( subjNamTab, helpText, color, labHRef, numFields, labText) )
		else:
			stream.write( pattArray[1] % ( subjNamTab, helpText, color, numFields, labText ) )
	except UnicodeEncodeError:
		sys.stderr.write("WritePatterned UnicodeEncodeError: Encoding=%s\n" % sys.getdefaultencoding() )
		return

	for key in lib_util.natural_sorted(dictLines):
		try:
			# Brackets have a specific role in "dot" files syntax.
			# So this escapes them, to be correctly displayed by the browser.
			dictLines[key] = dictLines[key].replace("[","&#91;").replace("]","&#93;")
			stream.write( "<tr>%s</tr>" % dictLines[key] )
		except UnicodeEncodeError:
			stream.write( "<tr><td>Unicode error encoding=%s</td></tr>" % sys.getdefaultencoding() )

	stream.write( "</table> > ] \n" )

################################################################################

