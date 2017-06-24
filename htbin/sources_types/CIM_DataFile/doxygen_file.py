#!/usr/bin/python

"""
DOxygen parsing
"""

import os
import sys
import lib_common
import lib_util
from lib_properties import pc
import lib_doxygen

doxygenExtensions = [
	".c",".cc",".cxx",".cpp",".c++",".java",".ii",".ixx",".ipp",".i++",
	".inl",".idl",".ddl",".odl",
	".h",".hh",".hxx",".hpp",".h++",
	".cs",".d",".php",".php4",".php5",".phtml",".inc",
	".m",".markdown",".md",".mm",".dox",
	".py",".pyw",
	".f90",".f",".for",
	".tcl",".vhd",".vhdl",".ucf",".qsf",".as",".js"
]

def Usable(entity_type,entity_ids_arr):
	"""Not a source file"""
	filNam = entity_ids_arr[0]
	filExt = os.path.splitext(filNam)[1]
	if filExt.lower() in doxygenExtensions:
		return True

	return os.path.isdir(filNam)

def Main():
	paramkeyRecursive = "Recursive exploration"
	paramkeyExplodeClasses = "Explode classes members"

	cgiEnv = lib_common.CgiEnv(
		parameters = { paramkeyRecursive : False, paramkeyExplodeClasses : False })

	paramExplodeClasses = int(cgiEnv.GetParameters( paramkeyExplodeClasses ))

	fileParam = cgiEnv.GetId()

	grph = cgiEnv.GetGraph()

	objectsByLocation = lib_doxygen.DoxygenMain(False,fileParam)

	directoryName = os.path.dirname(fileParam)
	rootNode = lib_common.gUriGen.FileUri( fileParam )

	lib_doxygen.CreateObjs(grph,rootNode,directoryName,objectsByLocation,paramExplodeClasses)

	# TODO: THE GENERATED GRAPH SHOULD BE MORE SIMILAR TO DOXYGEN'S.

	cgiEnv.OutCgiRdf("LAYOUT_RECT",[ pc.property_symbol_defined, pc.property_member ] )


if __name__ == '__main__':
	Main()
