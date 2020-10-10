#!/usr/bin/env python

"""
MSVC solution information

This returns general information about a Visual Studio solution file.
"""

# TODO: Use https://github.com/jhandley/pyvcproj/tree/master/vcproj
# Display projects.

import os
import sys
from sources_types import CIM_DataFile
import lib_util
import lib_common
from lib_properties import pc


def Usable(entity_type, entity_ids_arr):
	"""For a MSVC solution file ending with .sln"""
	file_path = entity_ids_arr[0]
	return file_path.endswith(".sln")


def Main():
	cgiEnv = lib_common.CgiEnv()
	fil_nam = cgiEnv.GetId()

	fil_node = lib_common.gUriGen.FileUri(fil_nam)

	grph = cgiEnv.GetGraph()

	cgiEnv.OutCgiRdf()


if __name__ == '__main__':
	Main()
