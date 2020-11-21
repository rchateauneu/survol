#!/usr/bin/env python

"""
Shared memory segments
"""

import sys
import rdflib
import lib_common
import lib_util
from lib_properties import pc
from sources_types import CIM_Process

def Main():
    cgiEnv = lib_common.CgiEnv()
    pid = int(cgiEnv.GetId())

    grph = cgiEnv.GetGraph()

    proc_obj = CIM_Process.PsutilGetProcObj(pid)

    node_process = lib_common.gUriGen.PidUri(pid)

    try:
        all_maps = proc_obj.memory_maps()
    except Exception as exc:
        lib_common.ErrorMessageHtml("get_memory_maps Pid=%d. Caught %s\n" % (pid, str(exc)))

    propMemoryRSS = lib_util.MakeProp("Resident Set Size")
    for map in all_maps:
        # This, because all Windows paths are "standardized" by us.
        # TODO: clean_map_path = lib_util.standardized_file_path(map.path)
        clean_map_path = map.path.replace("\\", "/")

        uri_mem_map = lib_common.gUriGen.MemMapUri(clean_map_path)

        grph.add((uri_mem_map, propMemoryRSS, rdflib.Literal(map.rss)))
        grph.add((node_process, pc.property_memmap, uri_mem_map))

    cgiEnv.OutCgiRdf( "LAYOUT_SPLINE")

if __name__ == '__main__':
    Main()

