#!/usr/bin/python

"""
Object types
"""

import os
import sys
import rdflib

import lib_util
import lib_common
from lib_properties import pc

def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = rdflib.Graph()

	rootNode = lib_util.RootUri()

	# This assumes that we have no namespace.
	for entity_type in lib_util.ObjectTypes():
		if not lib_util.OntologyClassAvailable(entity_type):
			continue

		tmpNode = rootNode
		idx = 0

		while idx >= 0:
			nextSlash = entity_type.find( "/", idx + 1 )
			if nextSlash == -1:
				intermedType = entity_type
			else:
				intermedType = entity_type[ : nextSlash ]

			entityNode = lib_util.EntityClassNode(intermedType)
			grph.add( ( tmpNode, lib_common.pc.property_directory, entityNode ) )
			tmpNode = entityNode
			idx = nextSlash

	cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT")

if __name__ == '__main__':
	Main()
