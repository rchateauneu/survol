#!/usr/bin/python

"""
Search SQL queries from source files.
"""

import os
import os.path
import re
import sys
import lib_sql
import lib_util
import lib_common
import lib_modules
from lib_properties import pc

# Any type of source file can contain SQL queries.
extensionsSQLSourcesFiles = [
	".c",".cc",".cxx",".cpp",".c++",".java",".ii",".ixx",".ipp",".i++",
	".pc",".pcc"
	".inl",".idl",".ddl",".odl",
	".h",".hh",".hxx",".hpp",".h++",
	".cs",".d",".php",".php4",".php5",".phtml",".inc",
	".py",".pyw",
	".f90",".f",".for",
	".tcl",".as",".js",
	".sh",".csh",".bash",
	".sql",".pls",".pks"
]

def Usable(entity_type,entity_ids_arr):
	"""Filename must have proper file extension"""
	filNam = entity_ids_arr[0]
	filExt = os.path.splitext(filNam)[1]
	if filExt.lower() in extensionsSQLSourcesFiles:
		return True

	# On Unix, we could also check if the file is a Shell script, whatever the extension is.
	return os.path.isdir(filNam)

# There must be another script for object files and libraries,
# because the search should not be done in the entire file,
# but only in the DATA segment.



def Main():
	cgiEnv = lib_common.CgiEnv()
	filNam = cgiEnv.GetId()

	grph = cgiEnv.GetGraph()

	nodeFile = lib_common.gUriGen.FileUri(filNam)

	try:
		# The regular expressions are indexed with a key such as "INSERT", "SELECT" etc...
		# which gives a hint about what the query does, and is transformed into a RDF property.
		# Also, the regular expressions are compiled for better performence.
		# This creates an dictionary mapping the RDF property to the compiled regular expression.
		dictRegexSQL = lib_sql.SqlRegularExpressions()

		arrProps = []
		for rgxKey in dictRegexSQL:
			rgxSQL = dictRegexSQL[rgxKey]
			rgxProp = lib_common.MakeProp(rgxKey)
			arrProps.append(rgxProp)

			compiledRgx = re.compile(rgxSQL)

			opFil = open(filNam, 'r')
			for linFil in opFil:
				matchedSqls = compiledRgx.findall(linFil)

				# For the moment, we just print the query.
				for sqlQry in matchedSqls:
					# grph.add( ( node_process, pc.property_rdf_data_nolist1, nodePortalWbem ) )
					grph.add( ( nodeFile, rgxProp, lib_common.NodeLiteral(sqlQry) ) )

	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Error:%s. Protection ?"%str(exc))

	cgiEnv.OutCgiRdf("LAYOUT_RECT",arrProps)

if __name__ == '__main__':
	Main()

