#!/usr/bin/env python

"""
Entry points displayed from nm command
"""

import os
import sys

import lib_nm
import lib_util
import lib_common
from lib_properties import pc

Usable = lib_util.UsableLinuxBinary

def AddKnown(grph, nodeSharedLib, symbolnam, file, type):
	symbolNode = lib_common.gUriGen.SymbolUri( lib_util.EncodeUri(symbolnam), file )
	grph.add( ( nodeSharedLib, pc.property_symbol_defined, symbolNode ) )
	grph.add( ( symbolNode, pc.property_symbol_type, lib_common.NodeLiteral(type) ) )

def AddUnknown(grph, nodeSharedLib, symbolnam):
	symbolNode = lib_common.gUriGen.SymbolUri( lib_util.EncodeUri(symbolnam), "*" )
	grph.add( ( nodeSharedLib, pc.property_symbol_undefined, symbolNode ) )

def Main():
	cgiEnv = lib_common.CgiEnv()
	fileSharedLib = cgiEnv.GetId()

	grph = cgiEnv.GetGraph()

	nodeSharedLib = lib_common.gUriGen.FileUri( fileSharedLib )

	cnt = 0
	for type,tail in lib_nm.GetSymbols(fileSharedLib):
		if type == 'T' or type == 't':
			AddKnown( grph, nodeSharedLib,tail, fileSharedLib, type )
			#"U" The symbol is undefined.
		elif type == 'U' :
			AddUnknown( grph, nodeSharedLib,tail )
		else:
			# Does not display all symbols because it is too much information.
			# AddKnown( tail, fileSharedLib, type )
			pass
		cnt += 1

	DEBUG("Nm: Processed %d lines", cnt)
	cgiEnv.OutCgiRdf("LAYOUT_RECT",[ pc.property_symbol_defined, pc.property_symbol_undefined] )

if __name__ == '__main__':
	Main()
