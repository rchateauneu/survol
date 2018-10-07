#!/usr/bin/python

"""
Search strings in text file.
"""

# The text strings are returned as RDF triples with the predicate: pc.property_string_occurrence
# The same concept can be applied to searches in SQL tables.
# The filter is a conceptually a plain regular expression.
# A parameter is the maximum number of results.
# If the regular expression is empty, it might possible return an error message,
# or the entire content file.

"""
On a besoin d une expression reguliere rentree a la main pour les tests et l utilisation
manuelle, sinon le script na pas de sens.
Toutefois, il faut tenir compte du filtre SparQL: S'il y a un filtre,
le parametre CGI est forcement absent, et inversement.
S'il y a un filtre, on peut calculer l'expression reguliere et empecher cgiEnv d'appliquer le filtre car ca ferait doubkle-emploi.
"""

import os
import os.path
import re
import sys
import lib_util
import lib_common
import lib_modules
from lib_properties import pc

def Main():
	paramkeyMaxOccurrences = "Maximum number of occurrences"
	paramkeyRegularExpression = "Regular expression"

	cgiEnv = lib_common.CgiEnv(
			parameters = { paramkeyMaxOccurrences : 100, paramkeyRegularExpression: "[a-zA-Z0-9]{5,}" } )

	maxOccurrences = cgiEnv.GetParameters( paramkeyMaxOccurrences )
	regExpr = cgiEnv.GetParameters( paramkeyRegularExpression )

	filNam = cgiEnv.GetId()

	grph = cgiEnv.GetGraph()

	nodeFile = lib_common.gUriGen.FileUri(filNam)

	try:

		# compiledRgx = re.compile(rgxSQL, re.IGNORECASE)
		# compiledRgx = re.compile("([a-zA-Z0-9]{5,})")
		compiledRgx = re.compile(regExpr)

		# Ou alors renvoyer un sous-niveau par chaine avec le niveau en-dessous qui contiendra les occurrences:
		# Un peu comme les dir qui ne sont pas clickables.

		cntLines = 1
		opFil = open(filNam, 'r')
		for linFil in opFil:
			cntLines += 1
			if cntLines > maxOccurrences:
				break
			matchedStrs = compiledRgx.findall(linFil)

			# TODO: For the moment, we just print the query. How can it be related to a database ?
			for oneStr in matchedStrs:
				# grph.add( ( node_process, pc.property_rdf_data_nolist1, nodePortalWbem ) )
				sys.stderr.write("oneStr=%s\n"%str(oneStr))
				nodeStr = lib_common.NodeLiteral(oneStr)
				grph.add( ( nodeFile, pc.property_string_occurrence, lib_common.NodeLiteral(oneStr) ) )

				# Ca marche mais on s en fout
				# grph.add( ( nodeStr, pc.property_string_occurrence, lib_common.NodeLiteral("kljhkljhlkj") ) )

		# grph.add( ( nodeFile, pc.property_com_entry, lib_common.gUriGen.FileUri("Tralala") ) )
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Error:%s. Protection ?"%str(exc))

	cgiEnv.OutCgiRdf("LAYOUT_RECT",[pc.property_string_occurrence])

if __name__ == '__main__':
	Main()

