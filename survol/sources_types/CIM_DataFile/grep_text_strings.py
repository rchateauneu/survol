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

# The default regular expression must return reasonable words
# as it is blindly used by the search engine.

# TODO: Use "grep" which is much faster.

# NOTE: For more generality, specify the regular expression with a SparQL query.

import os
import os.path
import re
import sys
import lib_util
import lib_common
import lib_properties
from lib_properties import pc

def Main():
	paramkeyMaxOccurrences = "Maximum number of occurrences"
	paramkeyRegularExpression = "Regular expression"

	cgiEnv = lib_common.CgiEnv(
			parameters = { paramkeyMaxOccurrences : 1000, paramkeyRegularExpression: "[a-zA-Z0-9]{5,}" } )

	# TODO: This must also return urls to display the next 1000 and previous 1000 words,
	# TODO: so that by following these links, the entire file will be analysed, once and once only.
	# TODO: Therefore, this could be replaced by the slice of lines to analyse ?


	maxOccurrences = cgiEnv.GetParameters( paramkeyMaxOccurrences )
	regExpr = cgiEnv.GetParameters( paramkeyRegularExpression )

	filNam = cgiEnv.GetId()
	DEBUG("filNam=%s regExpr=%s",filNam,regExpr)

	grph = cgiEnv.GetGraph()

	nodeFile = lib_common.gUriGen.FileUri(filNam)

	try:
		# TODO: Flag "Ignore case": re.compile(rgxSQL, re.IGNORECASE)
		compiledRgx = re.compile(regExpr)

		# TODO: Gets the matched expression with parentheses: re.compile("([a-zA-Z0-9]{5,})")

		cntLines = 1
		cntOccur = 1
		opFil = open(filNam, 'r')
		for linFil in opFil:
			cntLines += 1
			if cntOccur > maxOccurrences:
				break
			matchedStrs = compiledRgx.findall(linFil)

			for oneStr in matchedStrs:
				cntOccur += 1
				grph.add( ( nodeFile, pc.property_string_occurrence, lib_common.NodeLiteral( oneStr + ";" + str(cntLines) + ";" + str(cntOccur) ) ) )

				# TODO: Add intermediary node, counts the number of occurrences.
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Error:%s. Protection ?"%str(exc))

	DEBUG("cntLines=%d cntOccur=%d",cntLines,cntOccur)

	# TODO: Add an URL to the next and previous occurrences and lines, so it is possible to
	# TODO: ... search the entire file, once only, just be clicking: "Extra information"

	cgiEnv.OutCgiRdf("LAYOUT_RECT",[pc.property_string_occurrence])


if __name__ == '__main__':
	Main()

