"""
Component Object Model library of types
"""

import lib_common
from lib_properties import pc

def Graphic_colorbg():
    return "#3cb44b"


def EntityOntology():
    return (["Id"],)


def AddInfo(grph,node,entity_ids_arr):
    # TODO: We should use something like lib_common.ComTypeLibExtract(entity_id)
    dll_file_name = entity_ids_arr[0]

    file_node = lib_common.gUriGen.FileUri(dll_file_name)
    grph.add((file_node, pc.property_com_dll, node))
