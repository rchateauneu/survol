"""
Shareable memory segment
"""

import os
import sys
import psutil
import lib_util
import lib_common

from lib_properties import pc
from sources_types import CIM_Process


def EntityOntology():
    return (["Id"],)


def EntityName(entity_ids_arr):
    """This returns a nice name given the parameter of the object.
    Same logic as CIM_DataFile."""

    # TODO: How to display the full path ?
    entity_id = entity_ids_arr[0]
    # A file name can be very long, so it is truncated.
    file_basename = os.path.basename(entity_id)
    if file_basename == "":
        return entity_id
    else:
        return file_basename


def AddInfo(grph, node, entity_ids_arr):
    """A map file is associated to a file."""
    name_mapped_file = entity_ids_arr[0]

    exec_node = lib_common.gUriGen.FileUri(name_mapped_file)
    grph.add((node, lib_common.MakeProp("Mapped file"), exec_node))


def DisplayMappedProcesses(grph, file_name):
    """This displays all processes mapping a given filename.
    This simply iterates on processes, then on mapped files of each process.
    This is not very efficient but there is no other way."""
    grph.add((lib_common.nodeMachine, pc.property_hostname, lib_util.NodeLiteral(lib_util.currentHostname)))

    # This is also a file mapped into memory.
    uri_mapped_file = lib_common.gUriGen.FileUri(file_name)

    uri_mem_map = None

    try:
        statinfo = os.stat(file_name)
    except Exception as exc:
        grph.add((uri_mapped_file, lib_common.MakeProp("Error"), lib_util.NodeLiteral(str(exc))))
        return

    file_size = lib_util.AddSIUnit(statinfo.st_size, "B")
    grph.add((uri_mapped_file, pc.property_file_size, lib_util.NodeLiteral(file_size)))

    prop_memory_rss = lib_common.MakeProp("Resident Set Size")
    for proc in psutil.process_iter():
        pid = proc.pid

        try:
            all_maps = proc.memory_maps()
        except Exception as exc:
            # Probably psutil.AccessDenied
            continue

        for the_map in all_maps:
            # This, because all Windows paths are "standardized" by us.
            same_fil = lib_util.standardized_file_path(the_map.path) == lib_util.standardized_file_path(file_name)

            if same_fil:
                # Maybe this is the first mapping we have found.
                if uri_mem_map == None:
                    uri_mem_map = lib_common.gUriGen.MemMapUri(file_name)
                    grph.add((uri_mapped_file, pc.property_mapped, uri_mem_map))
                node_process = lib_common.gUriGen.PidUri(pid)

                # The property is reversed because of display.
                grph.add((uri_mem_map, pc.property_memmap, node_process))
                grph.add((node_process, pc.property_pid, lib_util.NodeLiteral(pid)))

                # Displays the RSS only if different from the file size.
                if map.rss != statinfo.st_size:
                    grph.add((node_process, prop_memory_rss, lib_util.NodeLiteral(map.rss)))
