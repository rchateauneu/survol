#!/usr/bin/python

"""
Returns minimal informaiton about a Windows symbol, using pefile Python library.
"""

import os
import os.path
import sys
import rdflib
import lib_uris
import lib_util
import lib_win32
import lib_common
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
	symbolFull = cgiEnv.GetId()

	# TODO: Maybe have two fields.
	# TODO: Temporary syntax.
	symbol, filNam = symbolFull.split("@")

	sys.stderr.write("symbol=%s filNam=%s\n"% (symbol,filNam) )

	grph = rdflib.Graph()

	symNode = lib_uris.gUriGen.SymbolUri( symbol, filNam )
	if filNam:
		filNode = lib_common.gUriGen.FileUri( filNam )
		grph.add( ( filNode, pc.property_symbol_defined, symNode ) )
		versStr = VersionString(filNam)
		grph.add( ( filNode, pc.property_information, rdflib.Literal(versStr) ) )

		pe = pefile.PE(filNam)

		try:
			for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
				sys.stderr.write("sym=%s\n"%sym)
				# sys.stderr.write("entry=%s\n"%str(entry.struct))
				if sym.name.lower() == symbol.lower():
					# docTxt = getattr(sym,"__doc__").replace(r"&#160;","")
					# Non-breaking space: A0	10100000	 	&#160;	&nbsp;
					# docTxt = getattr(sym,"__doc__").replace(chr(160),"")
					# Ca ne marche pas ...
					docTxt = getattr(sym,"__doc__")

					grph.add( ( symNode, pc.property_information,rdflib.Literal( docTxt ) ) )
					# grph.add( ( symNode, pc.property_information, rdflib.Literal(str(dir(sym))) ) )
					for key in ["name","offset","ordinal","forwarder"]:
						try:
							grph.add( ( symNode, lib_common.MakeProp(key), rdflib.Literal( getattr(sym,key) ) ) )
						except:
							pass
					break
		except AttributeError:
			sys.stderr.write("No import\n");
			pass

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()

