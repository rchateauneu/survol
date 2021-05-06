"""
Sqlite view
"""

import lib_uris
import lib_common
from sources_types import sqlite as survol_sqlite


def Graphic_colorbg():
    return "#FFCC66"


def EntityOntology():
    return (["File", "View"],)


def MakeUri(file_name, view_name):
    return lib_uris.gUriGen.node_from_dict("sqlite/view", {"File": file_name, "View": view_name})


def EntityName(entity_ids_arr):
    return entity_ids_arr[1] + "@" + survol_sqlite.ShortenSqliteFilename(entity_ids_arr[0])
