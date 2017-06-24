#!/usr/bin/python

"""
Memory map connected processes
"""

import lib_common
from sources_types import memmap

def Main():
	cgiEnv = lib_common.CgiEnv()
	memmapName = cgiEnv.GetId()

	grph = cgiEnv.GetGraph()

	memmap.DisplayMappedProcesses(grph,memmapName)

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
