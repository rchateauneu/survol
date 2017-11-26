#!/usr/bin/python

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

	# We have it but it is not needed at this place.
	# mime_type = cgiEnv.m_arguments["cgi_mime_type"]
	mime_type = cgiEnv.m_arguments["mode"]

	modeDisp = lib_util.GuessDisplayMode()
	sys.stderr.write("entity_mime.py mime_type=%s entity_type=%s modeDisp=%s\n"%(mime_type,entity_type,modeDisp))

	if not entity_type:
		lib_common.ErrorMessageHtml("entity_mime.py needs an object")

	entity_module = lib_util.GetEntityModule(entity_type)
	if not entity_module:
		lib_common.ErrorMessageHtml("entity_mime.py entity_type=%s needs a module" % (entity_type))

	try:
		entity_module.DisplayAsMime( grph, rootNode, entity_ids_arr )
	except:
		exc = sys.exc_info()[1]
		sys.stderr.write("entity_mime.py No DisplayAsMime for %s %s: %s\n"%( entity_type, entity_id, str(exc) ))

if __name__ == '__main__':
	Main()

