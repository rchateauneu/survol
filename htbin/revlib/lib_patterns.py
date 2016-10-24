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
	"com/registered_type_lib"                : ( "none",      "#CC99FF", "#CC99FF", 1, False ),
	"com/type_lib"                           : ( "none",      "#99FF99", "#99FF99", 1, False ),
	"com/type_lib_entry"                     : ( "none",      "#CCCCCC", "#CCCCCC", 1, False ),
	"CIM_Directory"                          : ( "folder",    "#88BBFF", "#88BBFF", 0, False ),
	# TODO: Not sure that ComposeTypes() will be kept. No real concept nor feature, not really used.
	lib_util.ComposeTypes("CIM_DataFile","script")   : ( "box",       "#FFFF66", "#FFFF66", 0, False ),
	"CIM_DataFile"                           : ( "note",      "#88BBFF", "#88BBFF", 0, False ),
	"group"                                  : ( "plain",     "#88BBFF", "#88BBFF", 0, False ),
	"CIM_ComputerSystem"                     : ( "signature", "#CCFFCC", "#CCFFCC", 0, False ),
	"memmap"                                 : ( "tab",       "#CCFFCC", "#CCFFCC", 0, False ),
	"odbc/dsn"                               : ( "tab",       "#CCFF11", "#CCFF11", 0, False ),
	"odbc/table"                             : ( "tab",       "#11FF11", "#CCFF11", 0, False ),
	"odbc/column"                            : ( "tab",       "#11FF11", "#44FF11", 0, False ),
	"odbc/procedure"                         : ( "tab",       "#11FF11", "#CC4411", 0, False ),
	"oracle/db"                              : ( "none",      "#FFCC66", "#FFCC66", 0, True ),
	"oracle/package"                         : ( "none",      "#FFCC66", "#88BBFF", 0, True ),
	"oracle/package_body"                    : ( "none",      "#FFCC66", "#CCCCCC", 0, True ),
	"oracle/schema"                          : ( "none",      "#FFCC66", "#CC99FF", 0, True ),
	"oracle/session"                         : ( "none",      "#FFCC66", "#FFCC66", 0, True ),
	"oracle/synonym"                         : ( "none",      "#FFCC66", "#FFCC66", 0, True ),
	"oracle/table"                           : ( "none",      "#FFCC66", "#FFCC66", 0, True ),
	"oracle/view"                            : ( "none",      "#FFCC66", "#FFCC66", 0, True ),
	"CIM_LogicalDisk"                        : ( "box3d",     "#FFCCFF", "#FFCC66", 0, False ),
	"smbfile"                                : ( "tab",       "#99CCFF", "#FFCC66", 0, True ),
	"smbserver"                              : ( "tab",       "#99CCFF", "#FFCC66", 0, True ),
	"smbshr"                                 : ( "tab",       "#99CCFF", "#FFCC66", 0, True ),
	"sqlite/table"                           : ( "none",      "#EEAAAA", "#FFCC66", 0, True ),
	"sqlite/column"                          : ( "none",      "#11FF11", "#FFCC66", 0, True ),
	"symbol"                                 : ( "none",      "#99FFCC", "#FFCC66", 0, False ),
	"user"                                   : ( "octagon",   "#EEAAAA", "#FFCC66", 0, False ),
	"Win32_Service"                          : ( "component", "#EEAAAA", "#FFCC66", 0, False ),
	"Win32_UserAccount"                      : ( "octagon",   "#EEAAAA", "#FFCC66", 0, True ),
}

dfltGraphParams =                              ( "none",      "#FFFFFF", "#99BB88", 1, False )


# Returns graphic parameters given a type without namespace.
# TODO: Allow to override and inherit specific members of the graphic pattern.
# Or have a more powerful graphic logic.
def TypeToGraphParams(typeWithoutNS):
	# Fastest access from the cache.
	try:
		return dictGraphParams[typeWithoutNS]
	except KeyError:
		pass

	# The tries a specific function in the module.
	grphPatt = None
	entity_module = lib_util.GetEntityModule(typeWithoutNS)
	if entity_module:
		try:
			grphPatt = entity_module.GraphicPattern()
		except AttributeError:
			# Maybe the function is not defined in this module.
			pass

	# No module and no function in the module.
	if not grphPatt:
		# Then take the upper level module.
		lastSlash = typeWithoutNS.rfind("/")
		if lastSlash > 0:
			# A type can inherit the graphic attributes of the upper level modules.
			choppedEntityType = typeWithoutNS[:lastSlash]
			# Recursive access, will happen once only for this type, ever.
			grphPatt =  TypeToGraphParams(choppedEntityType)
		else:
			grphPatt = dfltGraphParams

	# So next time we go straight to it because it will be in the set.
	dictGraphParams[typeWithoutNS] = grphPatt
	return grphPatt




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

