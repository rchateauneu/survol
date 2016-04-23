#!/usr/bin/python

import sys
import rdflib
import lib_common
import lib_util
from lib_common import pc
import lib_entities.lib_entity_Win32_Service

def Main():
	cgiEnv = lib_common.CgiEnv("Windows services")

	if not lib_util.isPlatformWindows:
		lib_common.ErrorMessageHtml("win32 Python library only on Windows platforms")

	grph = rdflib.Graph()

	lib_entities.lib_entity_Win32_Service.FullServiceNetwork(grph,None)

	# This routing is unreadable.
	# cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT")
	cgiEnv.OutCgiRdf(grph,"LAYOUT_SPLINE")
	# cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()
