#!/usr/bin/python

import os
import sys

import rdflib
import lib_elf
import lib_util
import lib_common
from lib_properties import pc




# This can be run from the command line like this:
# QUERY_STRING="SHAREDLIB=/usr/lib/libkdecore.so" htbin/sources/cgi_linux_nm.py
# The url must be encoded at this stage.

def Main():
	paramkeyMaxDepth = "Maximum depth"

	cgiEnv = lib_common.CgiEnv("Parsing ELF files to classes",
		parameters = { paramkeyMaxDepth : 1 })

	maxDepth = int(cgiEnv.GetParameters( paramkeyMaxDepth ))

	fileSharedLib = cgiEnv.GetId()

	grph = rdflib.Graph()

	nodeSharedLib = lib_common.gUriGen.FileUri( fileSharedLib )

	nodeGlobalNamespace = lib_common.gUriGen.ClassUri( "__global_namespace", fileSharedLib )
	grph.add( ( nodeSharedLib, pc.property_member, nodeGlobalNamespace ) )

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

	classAlreadyDone = set()

	cnt = 0
	for sym in listSyms:
		cnt += 1
		# TODO: Beaucoup de mal a parser de grandes librairies.
		# On va essayer de decouper par niveaux, en creant un nouveau script.
		# On affiche le premier niveau exclusivement, et on cree des liens vers
		# les classes (ou les namespaces) en mentionnant toujours le fichier.
		if cnt > 500:
			break

		lenSplit = len(sym.m_splt)
		if lenSplit > maxDepth:
			spltShort = sym.m_splt[:maxDepth]
			# TODO: Do the join only once.
			joinShort = "::".join(spltShort)
			# TODO: Should test and insert in one lookup only.
			if joinShort in classAlreadyDone:
				continue
			classAlreadyDone.add( joinShort )

			# So it cannot be a symbol but a class or a namespace.
			clsNod = ClassToNode( spltShort, maxDepth )

			# It is already linked to its ancestors.
		else:
			spltShort = sym.m_splt

			symNam = sym.m_splt[-1]

			symNod = lib_common.gUriGen.SymbolUri( lib_util.EncodeUri(symNam), fileSharedLib )
			grph.add( ( symNod, lib_common.MakeProp("Version"), rdflib.Literal(sym.m_vers) ) )
			if lenSplit > 1:
				clsNod = ClassToNode( sym.m_splt, lenSplit - 1 )
				grph.add( ( clsNod, pc.property_symbol_defined, symNod ) )
			else:
				grph.add( ( nodeGlobalNamespace, pc.property_symbol_defined, symNod ) )

	# TODO: Fix or check this when adding pc.property_member
	cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT",[ pc.property_symbol_defined, pc.property_member ] )
	#cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT",[ pc.property_symbol_defined ] )


if __name__ == '__main__':
	Main()
