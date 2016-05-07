#!/usr/bin/python

import os
import sys
import psutil
import socket
import urllib

import rdflib
import lib_nm
import lib_util
import lib_common
from lib_properties import pc




# TODO: Ca ne fonctionne pas encorer bien mais donne l'occasion de creer le type "class"
# qu'on va peut-etre reutiliser dans COM, et qui peut servir a structurer la memoire d'un process.







nodesByClass = {}

# The symbols must have been demangled.
def ExtractClass(symbol):
	# Should be very close to the end.
	last_par_close = symbol.rfind( ")" )
	if last_par_close == -1:
		return ""

	# Searches for the parenthesis matching the last one.
	cnt = 1
	last_par_open = last_par_close - 1
	while cnt != 0:
		if last_par_open == 0:
			return ""
		if symbol[last_par_open] == ")":
			cnt += 1
		elif symbol[last_par_open] == "(":
			cnt -= 1
		last_par_open -= 1


	# double_colon = symbol.rfind( "::", last_par_open )
	without_signature = symbol[ : last_par_open + 1 ]
	double_colon = without_signature.rfind( "::" )
	if double_colon == -1:
		return ""

	last_space = symbol[ : double_colon ].rfind( " " )
	if last_space == -1 :
		last_space = 0

	# classNam = symbol[ double_colon + 1 : last_par_open ]
	classNam = symbol[ last_space : double_colon ]
	sys.stderr.write( "symbol=%s without_signature=%s classNam=%s\n" % ( symbol, without_signature, classNam ) )
	return classNam


def AddSymbolInClass( grph, nodeSharedLib, symbol, file, prop ):
	symClass = ExtractClass( symbol )

	symbolNode = lib_common.gUriGen.SymbolUri( lib_util.EncodeUri(symbol), file )
	if symClass != "":
		try:
			nodeClass = nodesByClass[symClass]
		except KeyError:
			nodeClass = lib_common.gUriGen.ClassUri( symClass, file )
			nodesByClass[symClass] = nodeClass
			grph.add( ( nodeSharedLib, pc.property_member, nodeClass ) )
		grph.add( ( nodeClass, prop, symbolNode ) )
	else:
		grph.add( ( nodeSharedLib, prop, symbolNode ) )
	return symbolNode

def AddKnown(grph, nodeSharedLib, symbol, file, type):
	symbolNode = AddSymbolInClass( grph, nodeSharedLib, symbol, file, pc.property_symbol_defined )
	grph.add( ( symbolNode, pc.property_symbol_type, rdflib.Literal(type) ) )

def AddUnknown(grph, nodeSharedLib, symbol):
	symbolNode = AddSymbolInClass( grph, nodeSharedLib, symbol, "*", pc.property_symbol_undefined )

# This can be run from the command line like this:
# QUERY_STRING="SHAREDLIB=/usr/lib/libkdecore.so" htbin/sources/cgi_linux_nm.py
# The url must be encoded at this stage.

def Main():
	cgiEnv = lib_common.CgiEnv("nm command on executables and shared libraries (Linux), with classes")
	fileSharedLib = cgiEnv.GetId()

	grph = rdflib.Graph()

	nodeSharedLib = lib_common.gUriGen.FileUri( fileSharedLib )

	cnt = 0
	for type,tail in lib_nm.GetSymbols(fileSharedLib):
		if type == 'T' or type == 't':
			AddKnown( grph, nodeSharedLib, tail, fileSharedLib, type )
			#"U" The symbol is undefined.
		elif type == 'U' :
			AddUnknown( grph, nodeSharedLib, tail )
		else:
			# Does not display all symbols because it is too much information.
			# AddKnown( tail, fileSharedLib, type )
			pass
		cnt += 1

	sys.stderr.write("Nm: Processed %d lines\n" % cnt)
	cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT",[ pc.property_symbol_defined, pc.property_symbol_undefined] )


if __name__ == '__main__':
	Main()
