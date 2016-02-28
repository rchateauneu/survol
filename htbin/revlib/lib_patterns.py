# RGB colors here: http://www.pagetutor.com/common/bgcolors216.html

import sys
import lib_util

# We could also use dot record nodes.
# On the other hand, it is convenient to have some control on the final SVG code.
# NOTE: Could not set bgcolor for the shapes.
pattDict = {
	"addr"                                   : ( "rarrow",    "#FFFF99", "#FFFF99", 0, False ),
	"CIM_Process"                            : ( "component", "#99FF88", "#99FF88", 0, False ),
	"com_registered_type_lib"                : ( "none",      "#CC99FF", "#CC99FF", 1, False ),
	"com_type_lib"                           : ( "none",      "#99FF99", "#99FF99", 1, False ),
	"com_type_lib_entry"                     : ( "none",      "#CCCCCC", "#CCCCCC", 1, False ),
	lib_util.ComposeTypes("file","dir")      : ( "folder",    "#88BBFF", "#88BBFF", 0, False ),
	lib_util.ComposeTypes("file","script")   : ( "box",       "#FFFF66", "#FFFF66", 0, False ),
	"file"                                   : ( "note",      "#88BBFF", "#88BBFF", 0, False ),
	"group"                                  : ( "plain",     "#88BBFF", "#88BBFF", 0, False ),
	"CIM_ComputerSystem"                     : ( "signature", "#CCFFCC", "#CCFFCC", 0, False ),
	"memmap"                                 : ( "tab",       "#CCFFCC", "#CCFFCC", 0, False ),
	"odbc_dsn"                               : ( "tab",       "#CCFF11", "#CCFF11", 0, False ),
	"odbc_table"                             : ( "tab",       "#11FF11", "#CCFF11", 0, False ),
	"odbc_column"                            : ( "tab",       "#11FF11", "#44FF11", 0, False ),
	"odbc_procedure"                         : ( "tab",       "#11FF11", "#CC4411", 0, False ),
	"oracle_db"                              : ( "none",      "#FFCC66", "#FFCC66", 0, True ),
	"oracle_package"                         : ( "none",      "#FFCC66", "#88BBFF", 0, True ),
	"oracle_package_body"                    : ( "none",      "#FFCC66", "#CCCCCC", 0, True ),
	"oracle_schema"                          : ( "none",      "#FFCC66", "#CC99FF", 0, True ),
	"oracle_session"                         : ( "none",      "#FFCC66", "#FFCC66", 0, True ),
	"oracle_synonym"                         : ( "none",      "#FFCC66", "#FFCC66", 0, True ),
	"oracle_table"                           : ( "none",      "#FFCC66", "#FFCC66", 0, True ),
	"oracle_view"                            : ( "none",      "#FFCC66", "#FFCC66", 0, True ),
	"CIM_LogicalDisk"                        : ( "box3d",     "#FFCCFF", "#FFCC66", 0, False ),
	"smbfile"                                : ( "tab",       "#99CCFF", "#FFCC66", 0, True ),
	"smbserver"                              : ( "tab",       "#99CCFF", "#FFCC66", 0, True ),
	"smbshr"                                 : ( "tab",       "#99CCFF", "#FFCC66", 0, True ),
	"symbol"                                 : ( "none",      "#99FFCC", "#FFCC66", 0, False ),
	"user"                                   : ( "octagon",   "#EEAAAA", "#FFCC66", 0, False ),
	"Win32_Service"                          : ( "component", "#EEAAAA", "#FFCC66", 0, False ),
	"Win32_UserAccount"                      : ( "octagon",   "#EEAAAA", "#FFCC66", 0, True ),
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

def PatternNode(typeFull):
	# Maybe there is a namespace: "/:disk"
	type = typeFull.split(":")[-1]

	tp = TypeToPattern(type)
	if tp is None:
		return pattNodesDefault

	shape  = tp[0]
	colorfill  = tp[1]
	colorbg  = tp[2]
	border = tp[3]
	is_rounded = tp[4]

	# TODO: La premiere ligne est moche. Celle par defaut est mieux remplie.

	#return '%s [ shape=' + shape + ', tooltip="%s" style="filled" fillcolor="' + colorfill + '" color=%s label=< <table color="' + '#000000' + '"' + \
	#	" cellborder='0' cellspacing='0' border='" + str(border) + "'><tr>" + \
	#	'<td href="%s" bgcolor="' + colorbg + '" colspan="%d">%s</td>' + \
	#	"</tr>"
	if is_rounded:
		style = 'style="rounded,filled"'
	else:
		style = 'style="filled"'
	return '%s [ shape=' + shape + ', tooltip="%s", ' + style + ' fillcolor="' + colorfill + '" color=%s label=< <table color="' + '#000000' + '"' + \
		" cellborder='0' cellspacing='0' border='" + str(border) + "'><tr>" + \
		'<td href="%s" bgcolor="' + colorbg + '" colspan="%d">%s</td>' + \
		"</tr>"

def WritePatterned( stream, type, subjNamTab, hlp, col, labHRef, nbCols, labText, props ):
	patt = PatternNode(type)

	# PROBLEME: Le titre et les elements n ont pas forcement les memes couleurs.
	# Le cadre est celui du titre.

	try:
		stream.write( patt % ( subjNamTab, hlp, col, labHRef, nbCols, labText ) )
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

