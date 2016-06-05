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

cgiEnv = lib_common.CgiEnv()

grph = rdflib.Graph()

rootNode = lib_util.RootUri()

# This assumes that we have no namespace.
for entity_type in lib_util.ObjectTypes():
	if not lib_util.OntologyClassAvailable(entity_type):
		continue

	splitType = entity_type.split("/")

	tmpNode = rootNode
	for tp in splitType:
		entityNode = lib_util.EntityClassNode(tp)
		grph.add( ( tmpNode, lib_common.pc.property_directory, entityNode ) )
		tmpNode = entityNode


cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT")

