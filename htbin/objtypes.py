#!/usr/bin/python

"""
Object types
Hierarchy of generic Survol ontology classes.
"""

import os
import sys
import rdflib

import lib_util
import lib_common
from lib_properties import pc

# TODO: Do not display classes as always prefixed by "Generic " such as "Generic class Win32_Product".
# In the __init__.py, tell if this is also a WMI or WBEM class, maybe add the namespace etc...

# TODO: Display a __doc__ with each class, by importing the module.


def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = rdflib.Graph()

	rootNode = lib_util.RootUri()

	# This assumes that we have no namespace.
	for entity_type in lib_util.ObjectTypes():

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

			if intermedType == "rpm":
				sys.stderr.write("Doc %s\n" %(intermedType))

			entity_module = lib_util.GetEntityModule(intermedType)
			entDoc = entity_module.__doc__
			if entDoc:
				grph.add( ( entityNode, lib_common.pc.property_information, rdflib.Literal(entDoc) ) )

			# TODO: If this is a CIM class, add WMI or WBEM documentation, or add the link.

			tmpNode = entityNode
			idx = nextSlash

	cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT")

if __name__ == '__main__':
	Main()
