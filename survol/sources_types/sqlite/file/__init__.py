"""
Sqlite file
"""

import lib_uris
import lib_common
from sources_types import sqlite as survol_sqlite


def Graphic_colorbg():
    return "#FFCC66"


def EntityOntology():
    return (["File"],)


def MakeUri(file_name):
    return lib_uris.gUriGen.node_from_dict("sqlite/file", {"File": file_name})


def EntityName(entity_ids_arr):
    return survol_sqlite.ShortenSqliteFilename(entity_ids_arr[0])


def AddInfo(grph,node, entity_ids_arr):
    file_name = entity_ids_arr[0]
    node_file = lib_uris.gUriGen.FileUri(file_name)
    grph.add((node, lib_common.MakeProp("Path"), node_file))
