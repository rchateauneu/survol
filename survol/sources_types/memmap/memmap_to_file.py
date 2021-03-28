#!/usr/bin/env python

"""
Display information of the file associated to a memory map.
"""

import lib_uris
import lib_common
from sources_types import memmap
from sources_types import CIM_DataFile


def Main():
    cgiEnv = lib_common.ScriptEnvironment()
    memmap_name = cgiEnv.GetId()

    grph = cgiEnv.GetGraph()

    uri_memmap = lib_uris.gUriGen.MemMapUri(memmap_name)

    CIM_DataFile.AddInfo(grph, uri_memmap, [memmap_name])

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()

