#!/usr/bin/python

import os
import sys
import psutil
import socket
import urllib

import rdflib

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

	if not 'linux' in sys.platform:
		lib_common.ErrorMessageHtml("NM on Linux platform only")

	nodeSharedLib = lib_common.gUriGen.FileUri( fileSharedLib )

	nmCmd = "nm -DC " + fileSharedLib
	sys.stderr.write("Running %s\n" % nmCmd)
	stream = os.popen(nmCmd)

	# Just to have a sort of clean switch.

	# 0001d75c A __bss_start
	#         U __cxa_allocate_exception

	cnt = 0
	for line in stream:
		type = line[9].upper()
		tail = line[11:-1]

		#"A" The symbol's value is absolute, and will not be changed by further linking.
		#"B"
		#"b" The symbol is in the uninitialized data section (known as BSS).
		#"C" The symbol is common.  Common symbols are uninitialized data.  When linking, multiple common
		#    symbols may appear with the same name.  If the symbol is defined anywhere, the common symbols
		#    are treated as undefined references.
		#"D"
		#"d" The symbol is in the initialized data section.
		#"G"
		#"g" The symbol is in an initialized data section for small objects.  Some object file formats
		#    permit more efficient access to small data objects, such as a global int variable as opposed to
		#    a large global array.
		#"I" The symbol is an indirect reference to another symbol.  This is a GNU extension to the a.out
		#    object file format which is rarely used.
		#"i" The symbol is in a section specific to the implementation of DLLs.
		#"N" The symbol is a debugging symbol.
		#"p" The symbols is in a stack unwind section.
		#"R"
		#"r" The symbol is in a read only data section.
		#"S"
		#"s" The symbol is in an uninitialized data section for small objects.
		#"T"
		#"t" The symbol is in the text (code) section.
		if type == 'T' or type == 't':
			AddKnown( grph, nodeSharedLib,tail, fileSharedLib, type )
			#"U" The symbol is undefined.
		elif type == 'U' :
			AddUnknown( grph, nodeSharedLib,tail )
			#"V"
			#"v" The symbol is a weak object.  When a weak defined symbol is linked with a normal defined
			#    symbol, the normal defined symbol is used with no error.  When a weak undefined symbol is
			#    linked and the symbol is not defined, the value of the weak symbol becomes zero with no erro
			#    On some systems, uppercase indicates that a default value has been specified.
			#"W"
			#"w" The symbol is a weak symbol that has not been specifically tagged as a weak object symbol.
			#    When a weak defined symbol is linked with a normal defined symbol, the normal defined symbol is
			#    used with no error.  When a weak undefined symbol is linked and the symbol is not defined, the
			#    value of the symbol is determined in a system-specific manner without error.  On some systems,
			#    uppercase indicates that a default value has been specified.
			#"-" The symbol is a stabs symbol in an a.out object file.  In this case, the next values printed
			#    are the stabs other field, the stabs desc field, and the stab type.  Stabs symbols are used to
			#    hold debugging information.
			#"?" The symbol type is unknown, or object file format specific.
		else:
			# Does not display all symbols because it is too much information.
			# AddKnown( tail, fileSharedLib, type )
			pass
		cnt += 1

	sys.stderr.write("Nm: Processed %d lines\n" % cnt)
	cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT",[ pc.property_symbol_defined, pc.property_symbol_undefined] )

if __name__ == '__main__':
	Main()
