#!/usr/bin/python

"""
Remote machine Windows services
"""

import sys
import rdflib
import lib_util
import lib_common
from lib_common import pc
from sources_types import Win32_Service

def Main():
	cgiEnv = lib_common.CgiEnv()
	machineName = cgiEnv.GetId()

	grph = cgiEnv.GetGraph()

	# hostname = "Titi" for example
	# lib_win32.WNetAddConnect(machineName)

	try:
		Win32_Service.FullServiceNetwork(grph,machineName)
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("win32 "+machineName+" services:"+str(exc))

	# cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT")
	# cgiEnv.OutCgiRdf(grph)
	cgiEnv.OutCgiRdf(grph,"LAYOUT_SPLINE")

if __name__ == '__main__':
	Main()

  
