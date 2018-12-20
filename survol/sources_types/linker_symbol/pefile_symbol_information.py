#!/usr/bin/python

"""
Windows symbol information, with pefile package.
"""

import re
import os
import os.path
import sys
import lib_uris
import lib_util
import lib_win32
import lib_common
import string
import lib_pefile
import lib_symbol
from lib_properties import pc

import pefile
import win32api

# This can run on a PE file only.
def Usable(entity_type,entity_ids_arr):
	"""Can run on a pe file only"""

	try:
		# This is a bit hard-coded, the file comes second, and is not mandatory.
		filNam = entity_ids_arr[1]
		pe = pefile.PE(filNam)
		return True
	except Exception:
		return False

def VersionString(filNam):
	try:
		info = win32api.GetFileVersionInfo (filNam, "\\")
		ms = info['FileVersionMS']
		ls = info['FileVersionLS']
		return "%d.%d.%d.%d" % ( win32api.HIWORD (ms), win32api.LOWORD (ms), win32api.HIWORD (ls), win32api.LOWORD (ls) )
	except:
		return None

def FindPESymbol(filNam,symbolNam):
	try:
		pe = pefile.PE(filNam)

		for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
			# sys.stderr.write("sym=%s\n"%sym)
			# sys.stderr.write("entry=%s\n"%str(entry.struct))
			# if sym.name.lower() == symbol.lower():
			if  lib_pefile.UndecorateSymbol( sym.name ) == symbolNam:
				return sym
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("FindPESymbol %s %s. Caught:%s" % ( filNam, symbolNam, str(exc) ) )
	return None

def Main():

	cgiEnv = lib_common.CgiEnv()

	# "NtOpenObjectAuditAlarm%40C%3A\windows\system32\ntdll.dll"
	# Filename is optional.

	# The symbol is already demangled.
	symbol_encode = cgiEnv.m_entity_id_dict["Name"]
	# TODO: This should be packaged in lib_symbol.
	symbolNam = lib_util.Base64Decode(symbol_encode)
	filNam = cgiEnv.m_entity_id_dict["File"]

	DEBUG("symbol=%s filNam=%s", symbolNam,filNam)

	grph = cgiEnv.GetGraph()

	symNode = lib_uris.gUriGen.SymbolUri( symbolNam, filNam )

	if filNam:
		filNode = lib_common.gUriGen.FileUri( filNam )
		grph.add( ( filNode, pc.property_symbol_defined, symNode ) )
		versStr = VersionString(filNam)
		grph.add( ( filNode, pc.property_information, lib_common.NodeLiteral(versStr) ) )

		sym = FindPESymbol(filNam,symbolNam)

		if sym is not None:
			# docTxt = getattr(sym,"__doc__").replace(r"&#160;","")
			# Non-breaking space: A0	10100000	 	&#160;	&nbsp;
			# docTxt = getattr(sym,"__doc__").replace(chr(160),"")
			# TODO: Test this again ...
			docTxt = getattr(sym,"__doc__")

			# This string is filled with spaces and CR which are translated into "&#160;".
			docTxt = re.sub( '\s+', ' ', docTxt ).strip()

			grph.add( ( symNode, pc.property_information,lib_common.NodeLiteral( docTxt ) ) )

			# Possible values are "name","offset","ordinal","forwarder"
			try:
				fwrd = getattr(sym,"forwarder")
				grph.add( ( symNode, lib_common.MakeProp("Forwarder"), lib_common.NodeLiteral( fwrd ) ) )
			except:
				pass

			try:
				fwrd = getattr(sym,"ordinal")
				grph.add( ( symNode, lib_common.MakeProp("Ordinal"), lib_common.NodeLiteral( fwrd ) ) )
			except:
				pass

			( fulNam, lstArgs ) = lib_symbol.SymToArgs(symbolNam)
			if lstArgs:
				for arg in lstArgs:
					# TODO: Order of arguments must not be changed.
					argNode = lib_uris.gUriGen.ClassUri( arg, filNam )
					grph.add( ( symNode, pc.property_argument, argNode ) )

	cgiEnv.OutCgiRdf( "LAYOUT_RECT", [pc.property_argument] )

if __name__ == '__main__':
	Main()

