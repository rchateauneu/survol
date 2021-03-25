#!/usr/bin/env python

"""
Shared memory segments
"""

import sys
import rdflib

import lib_uris
import lib_common
import lib_util
from lib_properties import pc
from sources_types import CIM_Process


def Main():
    cgiEnv = lib_common.ScriptEnvironment()
    pid = int(cgiEnv.GetId())

    grph = cgiEnv.GetGraph()

    proc_obj = CIM_Process.PsutilGetProcObj(pid)

    node_process = lib_uris.gUriGen.PidUri(pid)

    try:
        all_maps = proc_obj.memory_maps()
    except Exception as exc:
        lib_common.ErrorMessageHtml("get_memory_maps Pid=%d. Caught %s\n" % (pid, str(exc)))

    propMemoryRSS = lib_common.MakeProp("Resident Set Size")
    for map_obj in all_maps:
        # This, because all Windows paths are "standardized" by us.
        # TODO: clean_map_path = lib_util.standardized_file_path(map_obj.path)
        clean_map_path = map_obj.path.replace("\\", "/")

        uri_mem_map = lib_uris.gUriGen.MemMapUri(clean_map_path)

        grph.add((uri_mem_map, propMemoryRSS, rdflib.Literal(map_obj.rss)))
        grph.add((node_process, pc.property_memmap, uri_mem_map))

    cgiEnv.OutCgiRdf( "LAYOUT_SPLINE")


if __name__ == '__main__':
    Main()

