#!/usr/bin/env python

"""
Java properties
"""

# NOT DONE.

# http://jpype.sourceforge.net/

import os
import os.path
import sys
import lib_util
import lib_uris
import lib_common
from lib_properties import pc

javaExtensions = {
	".java" : "Java source",
	".class": "Compiled Java"}

def Usable(entity_type,entity_ids_arr):
	"""Can run with Java files only"""

	filNam = entity_ids_arr[0]

	# But probably it is not enough and we should try to open it.
	filExt = os.path.splitext(filNam)[1]
	return filExt.lower() in javaExtensions

def AddAssociatedFiles(grph,node,filNam):
	DEBUG("AddAssociatedFiles %s",filNam)
	# sys.stderr.write("filNam=%s\n"%filNam)
	filenameNoExt, file_extension = os.path.splitext(filNam)

	for ext in javaExtensions:
		filAssocNam = filenameNoExt + ext

		DEBUG("filAssocNam=%s filNam=%s",filAssocNam,filNam)
		if filAssocNam.lower() != filNam.lower():
			if os.path.isfile(filAssocNam):
				DEBUG("Link filAssocNam=%s filNam=%s",filAssocNam,filNam)
				filAssocNode = lib_uris.gUriGen.FileUri(filAssocNam)
				grph.add( ( node, lib_common.MakeProp(javaExtensions[ext]), filAssocNode ) )



def Main():
	cgiEnv = lib_common.CgiEnv()

	javaFilNam = cgiEnv.GetId()

	# sys.stderr.write("dbFilNam=%s\n"%dbFilNam)

	grph = cgiEnv.GetGraph()

	filNode = lib_common.gUriGen.FileUri(javaFilNam)

	try:
		AddAssociatedFiles(grph,filNode,javaFilNam)
	except:
		exc = sys.exc_info()[0]
		lib_common.ErrorMessageHtml("File:%s Unexpected error:%s" % ( javaFilNam, str( exc ) ) )


	try:
		pass
	except:
		exc = sys.exc_info()[0]
		lib_common.ErrorMessageHtml("File:%s Unexpected error:%s" % ( javaFilNam, str( exc ) ) )

	cgiEnv.OutCgiRdf("LAYOUT_SPLINE")

if __name__ == '__main__':
	Main()

# https://en.wikipedia.org/wiki/Java_class_file
# Class files are identified by the following 4 byte header (in hexadecimal): CA FE BA BE (the first 4 entries in the table below).