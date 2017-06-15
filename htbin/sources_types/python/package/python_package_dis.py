#!/usr/bin/python

# INTERMEDIARY RELEASE. TO BE FINISHED.

"""
Python properties
"""

import sys
import rdflib
import importlib
import lib_common

from sources_types import python as survol_python
from sources_types.python import package as survol_python_package

try:
	import dis
except ImportError:
	pass

#def Usable(entity_type,entity_ids_arr):
#	"""Can run with Python files only"""
#
#	packageNam = entity_ids_arr[0]
#
#	return False


def Main():
	paramkeyMaxDepth = "Maximum depth"
	paramkeyDispPackages = "Display packages"
	paramkeyDispFiles = "Display files"

	cgiEnv = lib_common.CgiEnv(
			{ paramkeyMaxDepth : 1, paramkeyDispPackages: True, paramkeyDispFiles: False} )

	packageNam = cgiEnv.GetId()

	maxDepth = cgiEnv.GetParameters( paramkeyMaxDepth )
	dispPackages= cgiEnv.GetParameters( paramkeyDispPackages )
	dispFiles = cgiEnv.GetParameters( paramkeyDispFiles )

	packageNode = survol_python_package.MakeUri( packageNam )

	sys.stderr.write("packageNam=%s\n"%packageNam)

	grph = cgiEnv.GetGraph()

	tmpPyFil = lib_common.TmpFile("py_package_deps","py")
	tmpPyFilName = tmpPyFil.Name

	# This creates a temporary file which imports the package.
	tmpFd = open(tmpPyFilName,"w")
	tmpFd.write("import %s\n"%packageNam)
	tmpFd.close()

	survol_python_package.AddImportedModules(grph,packageNode,tmpPyFilName,maxDepth,dispPackages,dispFiles)

	try:
		the_module = importlib.import_module( packageNam )
	except:
		exc = sys.exc_info()[0]
		lib_common.ErrorMessageHtml("Package:%s Unexpected error:%s" % ( packageNam, str( exc ) ) )

	try:
		initFilNam = the_module.__file__
		filNode = lib_common.gUriGen.FileUri(initFilNam)
		grph.add( ( packageNode, survol_python_package.propPythonPackage, filNode ) )

		try:
			survol_python.AddAssociatedFiles(grph,filNode,initFilNam)
		except:
			exc = sys.exc_info()[0]
			lib_common.ErrorMessageHtml("File:%s Unexpected error:%s" % ( initFilNam, str( exc ) ) )
	except AttributeError:
		pass

	cgiEnv.OutCgiRdf("LAYOUT_SPLINE")

if __name__ == '__main__':
	Main()
