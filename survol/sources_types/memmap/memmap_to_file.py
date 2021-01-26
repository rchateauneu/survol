#!/usr/bin/env python

"""
Display information of the file associated to a memory map.
"""

import lib_common
from sources_types import memmap
from sources_types import CIM_DataFile


def Main():
	cgiEnv = lib_common.CgiEnv()
	memmap_name = cgiEnv.GetId()

	grph = cgiEnv.GetGraph()

	CIM_DataFile.AddInfo(grph, memmap_name)

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
