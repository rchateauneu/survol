#!/usr/bin/python

"""
Python package dependencies
"""

import os
import sys
import rdflib
import lib_common

from sources_types import python as survol_python
from sources_types.python import package as survol_python_package


def Usable(entity_type,entity_ids_arr):
	"""Can run with Python files only"""

	filNam = entity_ids_arr[0]

	# But probably it is not enough and we should try to open it.
	filExt = os.path.splitext(filNam)[1]
	return filExt.lower() in survol_python.pyExtensions

def Main():
	paramkeyMaxDepth = "Maximum depth"
	paramkeyDispPackages = "Display packages"
	paramkeyDispFiles = "Display files"

	cgiEnv = lib_common.CgiEnv(
			{ paramkeyMaxDepth : 1, paramkeyDispPackages: True, paramkeyDispFiles: False} )

	maxDepth = cgiEnv.GetParameters( paramkeyMaxDepth )
	dispPackages= cgiEnv.GetParameters( paramkeyDispPackages )
	dispFiles = cgiEnv.GetParameters( paramkeyDispFiles )

	pyFilNam = cgiEnv.GetId()

	# sys.stderr.write("dbFilNam=%s\n"%dbFilNam)

	grph = cgiEnv.GetGraph()

	filNode = lib_common.gUriGen.FileUri(pyFilNam)

	try:
		survol_python.AddAssociatedFiles(grph,filNode,pyFilNam)
	except:
		exc = sys.exc_info()[0]
		lib_common.ErrorMessageHtml("File:%s Unexpected error:%s" % ( pyFilNam, str( exc ) ) )

	survol_python_package.AddImportedModules(grph,filNode,pyFilNam,maxDepth,dispPackages,dispFiles)

	cgiEnv.OutCgiRdf("LAYOUT_SPLINE")

if __name__ == '__main__':
	Main()
