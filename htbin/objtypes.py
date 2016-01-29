#!/usr/bin/python

"""
Displays all object types
"""

import os
import sys
import rdflib

import lib_util
import lib_common
from lib_properties import pc

cgiEnv = lib_common.CgiEnv("Object types")

grph = rdflib.Graph()

rootNode = lib_util.RootUri()

# This assumes that we have no namespace.
for entity_type in lib_util.ObjectTypes():
	if not lib_util.OntologyClassAvailable(entity_type):
		continue

	# sys.stderr.write( "Type=%s\n" % entity_type )
	entityNode = lib_util.EntityClassNode(entity_type)

	grph.add( ( rootNode, lib_common.pc.property_directory, entityNode ) )

cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT")

