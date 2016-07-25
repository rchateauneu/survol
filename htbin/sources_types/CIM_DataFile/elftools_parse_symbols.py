#!/usr/bin/python

"""
Symbols in ELF files
"""

import os
import sys

import rdflib
import lib_elf
import lib_util
import lib_common
from lib_properties import pc

Usable = lib_util.UsableLinuxBinary

# This can be run from the command line like this:
# QUERY_STRING="SHAREDLIB=/usr/lib/libkdecore.so" htbin/sources/cgi_linux_nm.py
# The url must be encoded at this stage.

def Main():
	cgiEnv = lib_common.CgiEnv()

	fileSharedLib = cgiEnv.GetId()

	grph = rdflib.Graph()

	nodeSharedLib = lib_common.gUriGen.FileUri( fileSharedLib )

	try:
		readelf = lib_elf.ReadElf(fileSharedLib)
	except Exception:
		exc = sys.exc_info()[1]		
		lib_common.ErrorMessageHtml("Caught:"+str(exc))

	listNotes = readelf.display_notes()
	for pr in listNotes:
		infoMsg = pr[0] + ":" + pr[1]
		grph.add( ( nodeSharedLib, pc.property_information, rdflib.Literal(infoMsg) ) )

	listSyms, setClasses = readelf.display_symbol_tables()

	Main.nodesByClass = dict()

	def ClassToNode( classSplit, idx ):
		clsNam = "::".join( classSplit[ : idx ] )
		try:
			nodeClass = Main.nodesByClass[clsNam]
		except KeyError:
			nodeClass = lib_common.gUriGen.ClassUri( clsNam, fileSharedLib )
			# TODO: Create base classes ?
			Main.nodesByClass[clsNam] = nodeClass

			if idx > 1:
				nodeBaseClass = ClassToNode( classSplit, idx - 1 )
				grph.add( ( nodeBaseClass, pc.property_member, nodeClass ) )
			else:
				grph.add( ( nodeSharedLib, pc.property_member, nodeClass ) )

		return nodeClass

	cnt = 0
	for sym in listSyms:
		cnt += 1
		# TODO: Beaucoup de mal a parser de grandes librairies.
		# On va essayer de decouper par niveaux, en creant un nouveau script.
		# On affiche le premier niveau exclusivement, et on cree des liens vers
		# les classes (ou les namespaces) en mentionnant toujours le fichier.
		if cnt > 500:
			break

		if not sym.m_splt[0].startswith("std"):
			continue

		symNod = lib_common.gUriGen.SymbolUri( sym.m_name_demang, fileSharedLib )
		grph.add( ( symNod, lib_common.MakeProp("Version"), rdflib.Literal(sym.m_vers) ) )
		lenSplit = len(sym.m_splt)
		if lenSplit > 1:
			clsNod = ClassToNode( sym.m_splt, lenSplit - 1 )
			grph.add( ( clsNod, pc.property_symbol_defined, symNod ) )
		else:
			grph.add( ( nodeSharedLib, pc.property_symbol_defined, symNod ) )

	# TODO: Fix this when adding pc.property_member
	# cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT",[ pc.property_symbol_defined, pc.property_member ] )
	cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT",[ pc.property_symbol_defined ] )


if __name__ == '__main__':
	Main()
