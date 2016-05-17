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
import lib_common
from lib_properties import pc

def Main():

	cgiEnv = lib_common.CgiEnv("Symbol information")

	# "NtOpenObjectAuditAlarm%40C%3A\windows\system32\ntdll.dll"
	# Filename is optional.
	symbolFull = cgiEnv.GetId()

	symbol = cgiEnv.m_entity_id_dict["Name"]
	filNam = cgiEnv.m_entity_id_dict["File"]

	sys.stderr.write("symbol=%s filNam=%s\n"% (symbol,filNam) )

	grph = rdflib.Graph()

	symNode = lib_uris.gUriGen.SymbolUri( symbol, filNam )
	if filNam:
		filNode = lib_common.gUriGen.FileUri( filNam )
		grph.add( ( filNode, pc.property_symbol_defined, symNode ) )

	# TODO: Maybe the symbol name can be demangled to a class.

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()

