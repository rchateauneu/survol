#!/usr/bin/python

"""
Module dependencies
"""

import os
import os.path
import sys
import rdflib
import lib_util
import lib_common
import lib_modules
from lib_properties import pc

def Usable(entity_type,entity_ids_arr):
	"""Can run on a Sqlite database only"""

	filNam = entity_ids_arr[0]

	return filNam.endswith(".ko.xz")

def Main():
	cgiEnv = lib_common.CgiEnv()

	moduFilNam = cgiEnv.GetId()

	grph = cgiEnv.GetGraph()

	modudeps = lib_modules.Dependencies()

	for module_name in modudeps:
		file_parent = lib_modules.ModuleToNode(module_name)
		file_child = None
		for module_dep in modudeps[ module_name ]:
			if ( moduFilNam == module_name ) or ( moduFilNam == module_dep ):
				file_child = lib_modules.ModuleToNode(module_dep)

				grph.add( ( file_parent, pc.property_module_dep, file_child ) )
		# TODO: Ugly trick, otherwise nodes without connections are not displayed.
		# TODO: I think this is a BUG in the dot file generation. Or in RDF ?...
		if ( file_child is None ) and ( moduFilNam == module_name ) :
			grph.add( ( file_parent, pc.property_information, rdflib.Literal("") ) )

	cgiEnv.OutCgiRdf("LAYOUT_SPLINE")

if __name__ == '__main__':
	Main()
