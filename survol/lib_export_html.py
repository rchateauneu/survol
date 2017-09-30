import lib_util
import lib_exports
import lib_naming
import lib_kbase
import lib_properties
from lib_properties import pc

from lib_util import WrtAsUtf
from lib_util import WrtHeader

# Transforms a RDF graph into a HTML page.
#
# Report structure.
# Group objects by class.
# For class, display the number of objects and the list of these objects.
# For each object, the list of literal attributes in a table.
# Then the list of property then objects. Gather triplets by properties.
# Have little text for each property and the inverted property ?
# Maybe try to simplify this list by reverting the triplets.
#
#
#
#
def Grph2Html( page_title, error_msg, isSubServer, parameters, grph):
	# TODO: Est-ce necessaire d'utiliser WrtAsUtf au lieu de print() ?
	# Peut-etre oui, a cause des sockets?
	WrtHeader('text/html')
	# WrtAsUtf( "Content-type: text/html\n\n<head>" )
	WrtAsUtf( "<head>" )

	# TODO: Encode the HTML special characters.
	WrtAsUtf( "<title>" + page_title + "</title>")

	# TODO: Essayer de rassembler les literaux relatifs au memes noeuds, pour faire une belle presentation.

	WrtAsUtf( ' </head> <body>')

	WrtAsUtf('<table border="1">')

	WrtAsUtf('<tr><td colspan="3"><a href="' + lib_exports.ModedUrl("edit") + '">CGI parameters edition</a></td></tr>')

	for keyParam,valParam in parameters.items():
		WrtAsUtf('<tr><td>' + keyParam + '</td><td colspan="2">' + str(valParam) + '</td></tr>')

	WrtAsUtf('<tr><td colspan="3"><a href="' + lib_exports.ModedUrl("svg") + '">Content as SVG</a></td></tr>')
	WrtAsUtf('<tr><td colspan="3"><a href="' + lib_exports.ModedUrl("rdf") + '">Content as RDF</a></td></tr>')
	WrtAsUtf('<tr><td colspan="3">' + str(len(grph)) + ' nodes</td></tr>')

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

	WrtAsUtf( " </table> </body> </html> ")

################################################################################
