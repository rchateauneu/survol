# RGB colors here: http://www.pagetutor.com/common/bgcolors216.html

import sys
import lib_util

# Mettre dans sources_types. etc... ?
# Il faut que ce soit tres rapide !! lib_util.GetEntityModule(entity_type).AddInfo()

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
	lib_util.ComposeTypes("file","dir")      : ( "folder",    "#88BBFF", "#88BBFF", 0, False ),
	lib_util.ComposeTypes("file","script")   : ( "box",       "#FFFF66", "#FFFF66", 0, False ),
	"file"                                   : ( "note",      "#88BBFF", "#88BBFF", 0, False ),
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
def TypeToGraphParams(typeWithoutNS):
	try:
		return dictGraphParams[typeWithoutNS]
	except KeyError:
		return dfltGraphParams

	# TODO: Si on ne trouve pas, charger le module "sources_types/<type>/__init__.py"

# Builds a HTML pattern given graphic parameters.
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

	return '%s [ shape=' + shape + ', tooltip="%s", ' + style + ' fillcolor="' + colorfill + '" color=%s label=< <table color="' + '#000000' + '"' + \
		" cellborder='0' cellspacing='0' border='" + str(border) + "'><tr>" + \
		'<td href="%s" bgcolor="' + colorbg + '" colspan="%d">%s</td>' + \
		"</tr>"

dictTypeToPatterns = {}

# Returns a HTML pattern given an entity type.
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
		patt = BuildPatternNode(tp)
		dictTypeToPatterns[typeFull] = patt
		return patt

def WritePatterned( stream, type, subjNamTab, hlp, color, labHRef, nbCols, labText, props ):
	patt = PatternNode(type)

	# PROBLEME: Le titre et les elements n ont pas forcement les memes couleurs.
	# Le cadre est celui du titre.

	try:
		stream.write( patt % ( subjNamTab, hlp, color, labHRef, nbCols, labText ) )
	except UnicodeEncodeError:
		sys.stderr.write("WritePatterned UnicodeEncodeError: Encoding=%s\n" % sys.getdefaultencoding() )
		return

	# Maybe the keys will not be string.
	for key in sorted(props):
		try:
			stream.write( "<tr>%s</tr>" % props[key] )
		except UnicodeEncodeError:
			stream.write( "<tr><td>Unicode error encoding=%s</td></tr>" % sys.getdefaultencoding() )

	stream.write( "</table> > ] \n" )

################################################################################

