#!/usr/bin/python

"""
Processes mapping a file into memory
"""

import rdflib
import lib_common

from sources_types import memmap

def Main():
	cgiEnv = lib_common.CgiEnv()
	fileName = cgiEnv.GetId()

	grph = rdflib.Graph()

	memmap.DisplayMappedProcesses(grph,fileName)

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()
