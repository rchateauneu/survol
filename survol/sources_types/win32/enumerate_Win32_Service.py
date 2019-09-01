#!/usr/bin/env python

"""
Windows services
"""

import sys
import lib_common
import lib_util
from lib_properties import pc
from sources_types import Win32_Service

def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	Win32_Service.FullServiceNetwork(grph,None)

	# This routing is unreadable.
	# cgiEnv.OutCgiRdf("LAYOUT_RECT")
	cgiEnv.OutCgiRdf("LAYOUT_SPLINE")
	# cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
