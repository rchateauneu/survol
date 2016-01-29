#!/usr/bin/python

import sys
import rdflib
import lib_common
from lib_common import pc

cgiEnv = lib_common.CgiEnv("Windows services")

if not 'win' in sys.platform:
	lib_common.ErrorMessageHtml("win32 Python library only on Windows platforms")

import lib_entities.lib_entity_Win32_Service

grph = rdflib.Graph()

lib_entities.lib_entity_Win32_Service.FullServiceNetwork(grph,None)

# This routing is unreadable.
# cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT")
cgiEnv.OutCgiRdf(grph)
  