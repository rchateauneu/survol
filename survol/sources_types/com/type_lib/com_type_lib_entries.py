#!/usr/bin/python

"""
COM type library entries
"""

import os
import sys
import lib_common
import lib_util
from lib_properties import pc

import pythoncom
import win32con
import win32api

import lib_com_type_lib

Usable = lib_util.UsableWindows

def Main():
	cgiEnv = lib_common.CgiEnv()
	fname = cgiEnv.GetId()

	grph = cgiEnv.GetGraph()

	fnameMysteryNode = lib_common.gUriGen.ComTypeLibUri( fname )

	# TODO: Difficulte: On se retrouve qvec des dizaines d'entries,
	# qui correspondent a ces types, et on ne sait pas comment
	# les afficher differemment: C'est le meme probleme que les fichiers
	# qui sont des sous-classes.
	# DONC:
	# - Dans l'affichages des listes, prevoir des types de children:
	#   Le type du fichier, ou bien [Enumeration,CoClass,Dispatch] etc...
	# - Il faut que les sous-classes puissent etre definies par defaut.
	# - Pourquoi ne pas definir "file/dll", "file/exe" d'une part,
	#   "com_type_lib_entry/dispatch", "com_type_lib_entry/coclass" etc...
	#   Et dans la foulee, on remplace "BY_hostname" par "entities/hostname"
	# - L'affichage en liste HTML va detecter les entity_type dans les children
	#   d'un meme parent pour une propriete donnee, et va segmenter
	#   par entity_type et donc entity_subtype.


	HLITypeKinds = {
			pythoncom.TKIND_ENUM      : 'Enumeration',
			pythoncom.TKIND_RECORD    : 'Record',
			pythoncom.TKIND_MODULE    : 'Module',
			pythoncom.TKIND_INTERFACE : 'Interface',
			pythoncom.TKIND_DISPATCH  : 'Dispatch',
			pythoncom.TKIND_COCLASS   : 'CoClass',
			pythoncom.TKIND_ALIAS     : 'Alias',
			pythoncom.TKIND_UNION     : 'Union'
	  }


	try:
		tlb = pythoncom.LoadTypeLib(fname)
	except pythoncom.com_error:
		lib_common.ErrorMessageHtml("Cannot load:" + fname)

	for idx in range(tlb.GetTypeInfoCount()):
		try:
			infoTyp = tlb.GetTypeInfoType(idx)

			typNam = HLITypeKinds[infoTyp]

			sub_entity_type = lib_util.ComposeTypes("com", "type_lib_entry", typNam.lower() )

			nameComEntryUri = "%s_(%d)" % ( fname, idx )

			# TODO: Maybe this will be cleaner. Quick and dirty solution for the moment.
			# UriNodeCreatorName = "ComTypeLibEntry" + typNam + "Uri"
			# funcCreate = getattr( lib_common, UriNodeCreatorName )
			# entryNode = funcCreate( "%s_(%d)" % ( fname, idx ) )
			entryNode = lib_util.EntityUri(sub_entity_type,nameComEntryUri)

			name, doc, ctx, helpFile = tlb.GetDocumentation(idx)

			grph.add( (entryNode, pc.property_information, lib_common.NodeLiteral("name=%s" % name) ) )
			grph.add( (entryNode, pc.property_information, lib_common.NodeLiteral("type=%s" % typNam) ) )
			grph.add( (fnameMysteryNode, pc.property_com_entry, entryNode ) )

		except pythoncom.com_error:
			ret.append(browser.MakeHLI("The type info can not be loaded!"))

	cgiEnv.OutCgiRdf("LAYOUT_RECT")

if __name__ == '__main__':
	Main()
