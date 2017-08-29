#!/usr/bin/python

"""
Overview
"""

import os
import re
import sys
import rdflib
import lib_util
import lib_common
from lib_properties import pc

# We want only literal information which can be displayed in a table.

################################################################################

def AddInformation(grph,rootNode,entity_id, entity_type):
	entity_ids_arr = lib_util.EntityIdToArray( entity_type, entity_id )

	# Each entity type ("process","file" etc... ) can have a small library
	# of its own, for displaying a rdf node of this type.
	if entity_type:
		entity_module = lib_util.GetEntityModule(entity_type)
		if entity_module:
			try:
				# On veut garder uniquement les informations textuelles
				# qu'on peut afficher dans une table. Et en plus ce doit etre tres rapide.
				# En fait il faudrait virer rdflib, le remplacer
				# par un simple container.
				# On peut se roder en passant un pseudo-grph ?
				class FilterLiteralRdfGraph:
					#Init with a genuine rdflib graph.
					def __init__(self,grph,destNode):
						self.m_grph = grph
						self.m_node = destNode

					# If the information is not a literal, we could display the associated name.
					# Also, consider recursive tables.
					def Filter(self,subjRdf,objRdf):
						return (subjRdf == self.m_node) and isinstance(objRdf, (rdflib.term.Literal))

					# This filters only literal properties which points to or from our node.
					# This also ensures that theere is one node only, no links, because
					# of the way json documents are generated.
					# THE WHOLE SCRIPT MUST BE REPLACED BY A REAL JSON DOCUMENT,
					# TRANSFORMED INTO HTML.
					def add(self,trpl):
						# sys.stderr.write("Trying %s %s %s\n"% trpl)
						if self.Filter(trpl[0],trpl[2]):
							# sys.stderr.write("Adding %s %s %s\n"%trpl)
							self.m_grph.add(trpl)
						if self.Filter(trpl[2],trpl[0]):
							# sys.stderr.write("Adding %s %s %s\n"%trpl)
							self.m_grph.add((trpl[2],trpl[1],trpl[0]))

				pseudoGraph = FilterLiteralRdfGraph(grph,rootNode)

				entity_module.AddInfo( pseudoGraph, rootNode, entity_ids_arr )


			except AttributeError:
				exc = sys.exc_info()[1]
				sys.stderr.write("No AddInfo for %s %s: %s\n"%( entity_type, entity_id, str(exc) ))
	else:
		sys.stderr.write("No lib_entities for %s %s\n"%( entity_type, entity_id ))

def Main():
	# This can process remote hosts because it does not call any script, just shows them.
	cgiEnv = lib_common.CgiEnv(
					can_process_remote = True)
	entity_id = cgiEnv.m_entity_id
	entity_host = cgiEnv.GetHost()

	( nameSpace, entity_type, entity_namespace_type ) = cgiEnv.GetNamespaceType()

	grph = cgiEnv.GetGraph()

	rootNode = lib_util.RootUri()

	AddInformation(grph,rootNode,entity_id, entity_type )

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()

