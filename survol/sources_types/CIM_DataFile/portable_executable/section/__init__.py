"""
PE file section
"""

import os

import lib_uris
import lib_common


def EntityOntology():
    return (["Name", "Section"],)


def EntityName(entity_ids_arr):
    file_name = entity_ids_arr[0]
    section_name = entity_ids_arr[1]

    # A file name can be very long, so it is truncated.
    file_name_base = os.path.basename(file_name)
    return file_name_base + ":" + section_name


def MakeUri(file_name, section_name):
    return lib_uris.gUriGen.node_from_dict(
        "CIM_DataFile/portable_executable/section", {"Name" : file_name, "Section": section_name})
