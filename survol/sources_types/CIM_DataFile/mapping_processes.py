#!/usr/bin/python

"""
Processes mapping this file in memory
"""

import lib_common
from lib_properties import pc
from sources_types import memmap

def Main():
	cgiEnv = lib_common.CgiEnv()
	fileName = cgiEnv.GetId()

	grph = cgiEnv.GetGraph()

	memmap.DisplayMappedProcesses(grph,fileName)

	# cgiEnv.OutCgiRdf()
	cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_memmap] )

if __name__ == '__main__':
	Main()
