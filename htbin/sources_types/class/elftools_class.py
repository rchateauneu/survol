#!/usr/bin/python

"""
ELF files to class
"""

import os
import sys

import rdflib
import lib_elf
import lib_util
import lib_common
from lib_properties import pc

# TODO: This does not work for a Java class: Must check the file name and magic number ("CAFEBABE").
def Usable(entity_type,entity_ids_arr):
	#dirNam = entity_ids_arr[0]
	#return os.path.isdir(dirNam)
	return True

def Main():
	paramkeyMaxDepth = "Maximum depth"

	cgiEnv = lib_common.CgiEnv(
		parameters = { paramkeyMaxDepth : 2 })

	maxDepth = int(cgiEnv.GetParameters( paramkeyMaxDepth ))

	nameTopClass = cgiEnv.m_entity_id_dict["Name"]

	# An executable, shared library. Maybe static library.
	fileName = cgiEnv.m_entity_id_dict["File"]

	grph = cgiEnv.GetGraph()

	# This expects that the string is not a symbol name but a class or a namespace.
	# Otherwise we would have scan the list of symbols, to find out.
	# nodeTopClass = lib_common.gUriGen.ClassUri( nameTopClass, fileSharedLib )
	nodeSharedLib = lib_common.gUriGen.FileUri( fileName )

	try:
		readelf = lib_elf.ReadElf(fileName)
	except Exception:
		exc = sys.exc_info()[1]		
		lib_common.ErrorMessageHtml("Caught:"+str(exc))

        listNotes = readelf.display_notes()
        for pr in listNotes:
		infoMsg = pr[0] + ":" + pr[1]
		grph.add( ( nodeSharedLib, pc.property_information, rdflib.Literal(infoMsg) ) )

	# TODO: List of classes is not needed.
	# TODO: Just read the symbols we need.
        listSyms, setClasses = readelf.display_symbol_tables()

	Main.nodesByClass = dict()

	def ClassToNode( classSplit, idx ):
		clsNam = "::".join( classSplit[ : idx ] )
		try:
			nodeClass = Main.nodesByClass[clsNam]
		except KeyError:
			nodeClass = lib_common.gUriGen.ClassUri( clsNam, fileName )
			# TODO: Create base classes ?
			Main.nodesByClass[clsNam] = nodeClass

			if idx > 1:
				nodeBaseClass = ClassToNode( classSplit, idx - 1 )
				grph.add( ( nodeBaseClass, pc.property_member, nodeClass ) )
			else:
				grph.add( ( nodeSharedLib, pc.property_member, nodeClass ) )

		return nodeClass

	classAlreadyDone = set()

	classPrefix = nameTopClass + "::"
	lenPrefix = len( nameTopClass.split("::") )
	maxDepthTotal = maxDepth + lenPrefix

	# sys.stderr.write("top=%s\n" % nameTopClass)
	for sym in listSyms:
		# symName = "::".join(sym.m_splt)

		if not sym.m_name.startswith( classPrefix ):
			continue

		# sys.stderr.write("name=%s\n" % sym.m_name)

		lenSplit = len(sym.m_splt)
		if lenSplit > maxDepthTotal:
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

			# symNam = sym.m_splt[-1]
			# symNod = lib_common.gUriGen.SymbolUri( lib_util.EncodeUri(symNam), fileName )
			symNod = lib_common.gUriGen.SymbolUri( sym.m_name, fileName )
			grph.add( ( symNod, lib_common.MakeProp("Version"), rdflib.Literal(sym.m_vers) ) )
			if lenSplit > 1:
				clsNod = ClassToNode( sym.m_splt, lenSplit - 1 )
				grph.add( ( clsNod, pc.property_symbol_defined, symNod ) )
			else:
				grph.add( ( nodeGlobalNamespace, pc.property_symbol_defined, symNod ) )

	# TODO: Fix or check this when adding pc.property_member
	cgiEnv.OutCgiRdf("LAYOUT_RECT",[ pc.property_symbol_defined, pc.property_member ] )
	#cgiEnv.OutCgiRdf("LAYOUT_RECT",[ pc.property_symbol_defined ] )


if __name__ == '__main__':
	Main()
