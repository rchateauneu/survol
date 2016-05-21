#!/usr/bin/python

"""
Windows symbol information, with pefile package.
"""

import re
import os
import os.path
import sys
import rdflib
import lib_uris
import lib_util
import lib_win32
import lib_common
import base64
import string
import lib_pefile
import lib_symbol
from lib_properties import pc

try:
	import pefile
except ImportError:
	exc = sys.exc_info()[1]
	lib_common.ErrorMessageHtml("Cannot import pefile:"+str(exc))

try:
	import win32api
except ImportError:
	exc = sys.exc_info()[1]
	lib_common.ErrorMessageHtml("Cannot import win32api:"+str(exc))

def VersionString(filNam):
	try:
		info = win32api.GetFileVersionInfo (filNam, "\\")
		ms = info['FileVersionMS']
		ls = info['FileVersionLS']
		return "%d.%d.%d.%d" % ( win32api.HIWORD (ms), win32api.LOWORD (ms), win32api.HIWORD (ls), win32api.LOWORD (ls) )
	except:
		return None

def Main():

	cgiEnv = lib_common.CgiEnv("Symbol information (pefile)")

	# "NtOpenObjectAuditAlarm%40C%3A\windows\system32\ntdll.dll"
	# Filename is optional.

	# The symbol is already demangled.
	symbol_encode = cgiEnv.m_entity_id_dict["Name"]
	# TODO: This should be packaged in lib_symbol.
	symbol = base64.urlsafe_b64decode(symbol_encode)
	filNam = cgiEnv.m_entity_id_dict["File"]

	sys.stderr.write("symbol=%s filNam=%s\n"% (symbol,filNam) )

	grph = rdflib.Graph()

	symNode = lib_uris.gUriGen.SymbolUri( symbol, filNam )
	propArg = lib_common.MakeProp("Argument")

	if filNam:
		filNode = lib_common.gUriGen.FileUri( filNam )
		grph.add( ( filNode, pc.property_symbol_defined, symNode ) )
		versStr = VersionString(filNam)
		grph.add( ( filNode, pc.property_information, rdflib.Literal(versStr) ) )

		pe = pefile.PE(filNam)



		try:
			for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
				# sys.stderr.write("sym=%s\n"%sym)
				# sys.stderr.write("entry=%s\n"%str(entry.struct))
				# if sym.name.lower() == symbol.lower():
				if  lib_pefile.UndecorateSymbol( sym.name ) == symbol:

					# docTxt = getattr(sym,"__doc__").replace(r"&#160;","")
					# Non-breaking space: A0	10100000	 	&#160;	&nbsp;
					# docTxt = getattr(sym,"__doc__").replace(chr(160),"")
					# Ca ne marche pas ...
					docTxt = getattr(sym,"__doc__")

					# This string is filled with spaces and CR which are translated into "&#160;".
					docTxt = re.sub( '\s+', ' ', docTxt ).strip()

					grph.add( ( symNode, pc.property_information,rdflib.Literal( docTxt ) ) )

					# Possible values are "name","offset","ordinal","forwarder"
					try:
						fwrd = getattr(sym,"forwarder")
						grph.add( ( symNode, lib_common.MakeProp("Forwarder"), rdflib.Literal( fwrd ) ) )
					except:
						pass

					try:
						fwrd = getattr(sym,"ordinal")
						grph.add( ( symNode, lib_common.MakeProp("Ordinal"), rdflib.Literal( fwrd ) ) )
					except:
						pass

					( fulNam, lstArgs ) = lib_symbol.SymToArgs(symbol)
					for arg in lstArgs:
						argNode = lib_uris.gUriGen.ClassUri( arg, filNam )
						grph.add( ( symNode, propArg, argNode ) )

					break
		except AttributeError:
			sys.stderr.write("No import\n");
			pass

	cgiEnv.OutCgiRdf(grph, "LAYOUT_RECT", [propArg] )

if __name__ == '__main__':
	Main()

