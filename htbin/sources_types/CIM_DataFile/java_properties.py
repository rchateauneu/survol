#!/usr/bin/python

"""
Java properties
"""

import os
import os.path
import sys
import rdflib
import lib_util
import lib_uris
import lib_common
from lib_properties import pc

def Usable(entity_type,entity_ids_arr):
	"""Can run with Java files only"""

	filNam = entity_ids_arr[0]

	# But probably it is not enough and we should try to open it.
	filExt = os.path.splitext(filNam)[1]
	return filExt.upper() in [".JAVA",".CLASS"]

def Main():
	cgiEnv = lib_common.CgiEnv()

	javaFilNam = cgiEnv.GetId()

	# sys.stderr.write("dbFilNam=%s\n"%dbFilNam)

	grph = rdflib.Graph()

	filNode = lib_common.gUriGen.FileUri(javaFilNam)

	try:
		AddAssociatedFiles(grph,filNode,javaFilNam)
	except:
		exc = sys.exc_info()[0]
		lib_common.ErrorMessageHtml("File:%s Unexpected error:%s" % ( javaFilNam, str( exc ) ) )

	cgiEnv.OutCgiRdf(grph,"LAYOUT_SPLINE")

if __name__ == '__main__':
	Main()
