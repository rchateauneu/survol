#!/usr/bin/python

"""
Windows services
"""

import sys
import rdflib
import lib_util
import lib_common
from lib_common import pc

import lib_entities.lib_entity_Win32_Service

def Main():
	if not lib_util.isPlatformWindows:
		lib_common.ErrorMessageHtml("win32 Python library only on Windows platforms")

	cgiEnv = lib_common.CgiEnv()

	grph = rdflib.Graph()

	lib_entities.lib_entity_Win32_Service.FullServiceNetwork(grph,None)

	# This routing is unreadable.
	# cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT")
	cgiEnv.OutCgiRdf(grph,"LAYOUT_SPLINE")

if __name__ == '__main__':
	Main()
