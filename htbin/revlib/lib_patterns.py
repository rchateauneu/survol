# RGB colors here: http://www.pagetutor.com/common/bgcolors216.html

import sys
import lib_util

# We could also use dot record nodes.
# On the other hand, it is convenient to have some control on the final SVG code.
# NOTE: Could not set bgcolor for the shapes.

#                                                shape        colorfill  colorbg    border is_rounded
dictGraphParams = {
	"addr"                                   : ( "rarrow",    "#FFFF99", "#FFFF99", 0, False ),
	"CIM_Process"                            : ( "component", "#99FF88", "#99FF88", 0, False ),
	"CIM_Directory"                          : ( "folder",    "#88BBFF", "#88BBFF", 0, False ),
	# TODO: Not sure that ComposeTypes() will be kept. No real concept nor feature, not really used.
	lib_util.ComposeTypes("CIM_DataFile","script")   : ( "box",       "#FFFF66", "#FFFF66", 0, False ),
	"CIM_DataFile"                           : ( "note",      "#88BBFF", "#88BBFF", 0, False ),
	"group"                                  : ( "plain",     "#88BBFF", "#88BBFF", 0, False ),
	"CIM_ComputerSystem"                     : ( "signature", "#CCFFCC", "#CCFFCC", 0, False ),
	"memmap"                                 : ( "tab",       "#CCFFCC", "#CCFFCC", 0, False ),
	"CIM_LogicalDisk"                        : ( "box3d",     "#FFCCFF", "#FFCC66", 0, False ),
	"smbfile"                                : ( "tab",       "#99CCFF", "#FFCC66", 0, True ),
	"smbserver"                              : ( "tab",       "#99CCFF", "#FFCC66", 0, True ),
	"smbshr"                                 : ( "tab",       "#99CCFF", "#FFCC66", 0, True ),
	"symbol"                                 : ( "none",      "#99FFCC", "#FFCC66", 0, False ),
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


# Returns graphic parameters given a type without namespace.
# For example "Win32_Service", "oracle/package"
def TypeToGraphParams(typeWithoutNS):
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
def TypeToGraphParamsNoCache(typeWithoutNS):

	vecGraphFunctions = [
		"Graphic_shape","Graphic_colorfill","Graphic_colorbg","Graphic_border","Graphic_is_rounded"
	]

	vecProps = []
	for idxGrph in range(len(vecGraphFunctions)):
		gFuncName = vecGraphFunctions[idxGrph]
		grphFunc = TypeToGraphParamsNoCacheOneFunc(typeWithoutNS,gFuncName)

		if grphFunc:
			grphVal = grphFunc()
		else:
			# If no such function defined for this module and its ancestors.
			grphVal = dfltGraphParams[idxGrph]
		vecProps.append( grphVal )

	return vecProps


# For example "Graphic_shape" etc... This seeks for a function in this name.
# This searches in several modules, starting with the module of the entity,
# then the upper module etc...
def TypeToGraphParamsNoCacheOneFunc(typeWithoutNS,gFuncName):

	# for the first loop it takes the entire string.
	lastSlash = len(typeWithoutNS)
	while lastSlash > 0:

		topModule = typeWithoutNS[:lastSlash]
		choppedEntityType = typeWithoutNS[:lastSlash]

		# Loa the module of this entity to see if it defines the graphic function.
		entity_module = lib_util.GetEntityModule(choppedEntityType)

		if entity_module:
			try:
				gFuncAddr = getattr(entity_module,gFuncName)
				return gFuncAddr
			except AttributeError:
				pass

		# Then try the upper level module.
		lastSlash = typeWithoutNS.rfind("/",0,lastSlash)

	return None




# This returns an array of format string which are used to generate HTML code.
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

# TODO: Not sure this is useful as dictGraphParams can fulfil the same need.
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
		type = typeFull.split(":")[-1]
		tp = TypeToGraphParams(type)
		pattArray = BuildPatternNode(tp)
		dictTypeToPatterns[typeFull] = pattArray
		return pattArray

def WritePatterned( stream, type, subjNamTab, helpText, color, labHRef, numFields, labText, dictLines ):
	pattArray = PatternNode(type)

	# PROBLEME: Le titre et les elements n ont pas forcement les memes couleurs.
	# Le cadre est celui du titre.

	try:
		if labHRef != "":
			stream.write( pattArray[0] % ( subjNamTab, helpText, color, labHRef, numFields, labText) )
		else:
			stream.write( pattArray[1] % ( subjNamTab, helpText, color, numFields, labText ) )
	except UnicodeEncodeError:
		sys.stderr.write("WritePatterned UnicodeEncodeError: Encoding=%s\n" % sys.getdefaultencoding() )
		return

	# Maybe the keys will not be string.
	for key in sorted(dictLines):
		try:
			stream.write( "<tr>%s</tr>" % dictLines[key] )
		except UnicodeEncodeError:
			stream.write( "<tr><td>Unicode error encoding=%s</td></tr>" % sys.getdefaultencoding() )

	stream.write( "</table> > ] \n" )

################################################################################

