#!/usr/bin/python

"""
Memory map connected processes
"""

import rdflib
import lib_common
from sources_types import memmap

def Main():
	cgiEnv = lib_common.CgiEnv()
	memmapName = cgiEnv.GetId()

	grph = rdflib.Graph()

	memmap.DisplayMappedProcesses(grph,memmapName)

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()
