"""
Sqlite table column
"""

import lib_uris
import lib_common
from sources_types import sqlite as survol_sqlite


def Graphic_colorbg():
    return "#FFCC66"


def EntityOntology():
    return (["File", "Table", "Column"],)


def MakeUri(file_name, table_name, column_name):
    return lib_uris.gUriGen.node_from_dict(
        "sqlite/column", {"File": file_name, "Table": table_name, "Column": column_name})


def EntityName(entity_ids_arr):
    return entity_ids_arr[1] + "." + entity_ids_arr[2] + "@" + survol_sqlite.ShortenSqliteFilename(entity_ids_arr[0])

