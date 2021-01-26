#!/usr/bin/env python

"""
Memory map connected processes
"""

import lib_common
from sources_types import memmap


def Main():
    cgiEnv = lib_common.CgiEnv()
    memmap_name = cgiEnv.GetId()

    grph = cgiEnv.GetGraph()

    memmap.DisplayMappedProcesses(grph, memmap_name)

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
