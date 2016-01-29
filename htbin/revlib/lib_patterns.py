# RGB colors here: http://www.pagetutor.com/common/bgcolors216.html

import lib_util

# We could also use dot record nodes.
# On the other hand, it is convenient to have some control on the final SVG code.
# NOTE: Could not set bgcolor for the shapes.
pattDict = {
	"addr"                                   : ( "rarrow",    "#FFFF99", "#FFFF99", 0 ),
	"CIM_Process"                            : ( "component", "#99FF88", "#99FF88", 0 ),
	"com_registered_type_lib"                : ( "none",      "#CC99FF", "#CC99FF", 1 ),
	"com_type_lib"                           : ( "none",      "#99FF99", "#99FF99", 1 ),
	"com_type_lib_entry"                     : ( "none",      "#CCCCCC", "#CCCCCC", 1 ),
	lib_util.ComposeTypes("file","dir")      : ( "folder",    "#88BBFF", "#88BBFF", 0 ),
	lib_util.ComposeTypes("file","script")   : ( "box",       "#FFFF66", "#FFFF66", 0 ),
	"file"                                   : ( "note",      "#88BBFF", "#88BBFF", 0 ),
	"group"                                  : ( "plain",     "#88BBFF", "#88BBFF", 0 ),
	"CIM_ComputerSystem"                     : ( "signature", "#CCFFCC", "#CCFFCC", 0 ),
	"memmap"                                 : ( "tab",       "#CCFFCC", "#CCFFCC", 0 ),
	"oracle_db"                              : ( "none",      "#FFCC66", "#FFCC66", 0 ),
	"oracle_package"                         : ( "none",      "#FFCC66", "#88BBFF", 0 ),
	"oracle_package_body"                    : ( "none",      "#FFCC66", "#CCCCCC", 0 ),
	"oracle_schema"                          : ( "none",      "#FFCC66", "#CC99FF", 0 ),
	"oracle_session"                         : ( "none",      "#FFCC66", "#FFCC66", 0 ),
	"oracle_synonym"                         : ( "none",      "#FFCC66", "#FFCC66", 0 ),
	"oracle_table"                           : ( "none",      "#FFCC66", "#FFCC66", 0 ),
	"oracle_view"                            : ( "none",      "#FFCC66", "#FFCC66", 0 ),
	"partition"                              : ( "box3d",     "#FFCCFF", "#FFCC66", 0 ),
	"smbfile"                                : ( "tab",       "#99CCFF", "#FFCC66", 0 ),
	"smbserver"                              : ( "tab",       "#99CCFF", "#FFCC66", 0 ),
	"smbshr"                                 : ( "tab",       "#99CCFF", "#FFCC66", 0 ),
	"symbol"                                 : ( "none",      "#99FFCC", "#FFCC66", 0 ),
	"user"                                   : ( "octagon",   "#EEAAAA", "#FFCC66", 0 ),
	"Win32_Service"                          : ( "component", "#EEAAAA", "#FFCC66", 0 ),
}

pattNodesDefault = "%s [ shape=none, tooltip=\"%s\" color=%s label=< <table color='#666666'" + \
	" cellborder='0' cellspacing='0' border='1'><tr>" + \
	"<td href='%s' bgcolor='#99BB88' colspan='%d'>%s</td>" + \
	"</tr>"

def TypeToPattern(type):
	try:
		return pattDict[type]
	except KeyError:
		return None

def PatternNode(type):
	tp = TypeToPattern(type)
	if tp is None:
		return pattNodesDefault

	shape  = tp[0]
	colorfill  = tp[1]
	colorbg  = tp[2]
	border = tp[3]

	# TODO: La premiere ligne est moche. Celle par defaut est mieux remplie.

	#return '%s [ shape=' + shape + ', tooltip="%s" style="filled" fillcolor="' + colorfill + '" color=%s label=< <table color="' + '#000000' + '"' + \
	#	" cellborder='0' cellspacing='0' border='" + str(border) + "'><tr>" + \
	#	'<td href="%s" bgcolor="' + colorbg + '" colspan="%d">%s</td>' + \
	#	"</tr>"
	return '%s [ shape=' + shape + ', tooltip="%s" style="filled" fillcolor="' + colorfill + '" color=%s label=< <table color="' + '#000000' + '"' + \
		" cellborder='0' cellspacing='0' border='" + str(border) + "'><tr>" + \
		'<td href="%s" bgcolor="' + colorbg + '" colspan="%d">%s</td>' + \
		"</tr>"

def DoTheWrite( stream, patt, subjNamTab, hlp, col, labHRef, nbCols, labText, props ):
	stream.write( patt % ( subjNamTab, hlp, col, labHRef, nbCols, labText ) )
	for key in sorted(props):
		stream.write( "<tr>%s</tr>" % props[key] )

	stream.write( "</table> > ] \n" )

def WritePatterned( stream, type, subjNamTab, hlp, col, labHRef, nbCols, labText, props ):
	patt = PatternNode(type)

	try:
		DoTheWrite( stream, patt, subjNamTab, hlp, col, labHRef, nbCols, labText, props )
	except UnicodeEncodeError:
		DoTheWrite( stream, patt, subjNamTab, hlp, col, "labHRef", 1, "labText", {} )

################################################################################

