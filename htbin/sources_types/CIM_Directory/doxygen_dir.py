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


def Main():
	paramkeyRecursive = "Recursive exploration"
	paramkeyExplodeClasses = "Explode classes members"

	cgiEnv = lib_common.CgiEnv(
		parameters = { paramkeyRecursive : False, paramkeyExplodeClasses : False })

	paramRecursiveExploration = int(cgiEnv.GetParameters( paramkeyRecursive ))
	paramExplodeClasses = int(cgiEnv.GetParameters( paramkeyExplodeClasses ))

	fileParam = cgiEnv.GetId()

	grph = cgiEnv.GetGraph()

	objectsByLocation = lib_doxygen.DoxygenMain(paramRecursiveExploration,fileParam)

	directoryName = fileParam
	rootNode = lib_common.gUriGen.DirectoryUri( directoryName )

	lib_doxygen.CreateObjs(grph,rootNode,directoryName,objectsByLocation,paramExplodeClasses)

	# TODO: THE GENERATED GRAPH SHOULD BE MORE SIMILAR TO DOXYGEN'S.

	cgiEnv.OutCgiRdf("LAYOUT_RECT",[ pc.property_symbol_defined, pc.property_member ] )


if __name__ == '__main__':
	Main()
