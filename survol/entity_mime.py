#!/usr/bin/env python

"""
Overview
"""

import os
import re
import sys
import lib_util
import lib_common
from lib_properties import pc

def Main():
	cgiEnv = lib_common.CgiEnv()
	entity_id = cgiEnv.m_entity_id
	entity_host = cgiEnv.GetHost()

	( nameSpace, entity_type, entity_namespace_type ) = cgiEnv.GetNamespaceType()

	grph = cgiEnv.GetGraph()

	rootNode = lib_util.RootUri()

	entity_ids_arr = lib_util.EntityIdToArray( entity_type, entity_id )

	modeDisp = lib_util.GuessDisplayMode()
	DEBUG("entity_mime.py entity_type=%s modeDisp=%s",entity_type,modeDisp)

	if not entity_type:
		lib_common.ErrorMessageHtml("entity_mime.py needs an object")

	entity_module = lib_util.GetEntityModule(entity_type)
	if not entity_module:
		lib_common.ErrorMessageHtml("entity_mime.py entity_type=%s needs a module" % (entity_type))

	try:
		entity_module.DisplayAsMime( grph, rootNode, entity_ids_arr )
	except:
		exc = sys.exc_info()[1]
		ERROR("entity_mime.py No DisplayAsMime for %s %s: %s", entity_type, entity_id, str(exc) )
		lib_common.ErrorMessageHtml("entity_mime.py No DisplayAsMime for %s %s: %s\n"%( entity_type, entity_id, str(exc) ))

if __name__ == '__main__':
	Main()

