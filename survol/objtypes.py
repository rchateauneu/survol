#!/usr/bin/python

"""
Object types
Hierarchy of generic Survol ontology classes.
"""

import os
import sys

import lib_util
import lib_common
from lib_properties import pc

# TODO: Do not display classes as always prefixed by "Generic " such as "Generic class Win32_Product".
# In the __init__.py, tell if this is also a WMI or WBEM class, maybe add the namespace etc...

# TODO: Display a __doc__ with each class, by importing the module.


def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

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

			try:
				# This reloads all classes without cache because we want to see the error message.
				entity_module = lib_util.GetEntityModuleNoCacheNoCatch(entity_type)
				entDoc = entity_module.__doc__
			except:
				exc = sys.exc_info()[1]
				entDoc = "Error:"+str(exc)

			if entDoc:
				grph.add( ( entityNode, lib_common.pc.property_information, lib_common.NodeLiteral(entDoc) ) )

			# TODO: If this is a CIM class, add WMI or WBEM documentation, or add the link.

			tmpNode = entityNode
			idx = nextSlash

	cgiEnv.OutCgiRdf("LAYOUT_RECT")

if __name__ == '__main__':
	Main()
