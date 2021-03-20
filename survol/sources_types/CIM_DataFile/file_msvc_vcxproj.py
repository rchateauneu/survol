#!/usr/bin/env python

"""
MSVC project information

This returns general information about a Visual Studio project file.
"""

# TODO: Use https://github.com/jhandley/pyvcproj/tree/master/vcproj
# Display dependent projects.

import os
import sys
from sources_types import CIM_DataFile
import lib_util
import lib_common
from lib_properties import pc


def Usable(entity_type, entity_ids_arr):
    """For a MSVC project file ending with .vcxproj"""
    file_path = entity_ids_arr[0]
    return file_path.endswith(".vcxproj")


def Main():
    cgiEnv = lib_common.ScriptEnvironment()
    fil_nam = cgiEnv.GetId()

    fil_node = lib_common.gUriGen.FileUri(fil_nam)

    grph = cgiEnv.GetGraph()

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
