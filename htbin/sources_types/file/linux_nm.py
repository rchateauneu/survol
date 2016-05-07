#!/usr/bin/python

import os
import os.path
import sys
import psutil
import socket
import urllib

import rdflib
import lib_nm
import lib_util
import lib_common
from lib_properties import pc

def AddKnown(grph, nodeSharedLib, symbol, file, type):
	symbolNode = lib_common.gUriGen.SymbolUri( lib_util.EncodeUri(symbol), file )
	grph.add( ( nodeSharedLib, pc.property_symbol_defined, symbolNode ) )
	grph.add( ( symbolNode, pc.property_symbol_type, rdflib.Literal(type) ) )

def AddUnknown(grph, nodeSharedLib, symbol):
	symbolNode = lib_common.gUriGen.SymbolUri( lib_util.EncodeUri(symbol), "*" )
	grph.add( ( nodeSharedLib, pc.property_symbol_undefined, symbolNode ) )

# This can be run from the command line like this:
# QUERY_STRING="SHAREDLIB=/usr/lib/libkdecore.so" htbin/sources/cgi_linux_nm.py
# The url must be encoded at this stage.

def Main():
	cgiEnv = lib_common.CgiEnv("nm command on executables and shared libraries (Linux)")
	fileSharedLib = cgiEnv.GetId()

	grph = rdflib.Graph()

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

	sys.stderr.write("Nm: Processed %d lines\n" % cnt)
	cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT",[ pc.property_symbol_defined, pc.property_symbol_undefined] )

if __name__ == '__main__':
	Main()
