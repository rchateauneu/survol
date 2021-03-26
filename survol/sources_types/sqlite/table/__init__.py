"""
Sqlite table
"""

import lib_uris
import lib_common
from sources_types import sqlite as survol_sqlite
from sources_types.sqlite import file as sqlite_file


def Graphic_colorbg():
    return "#FFCC66"


def EntityOntology():
    return (["File", "Table"],)


def MakeUri(file_name, table_name):
    return lib_uris.gUriGen.UriMakeFromDict("sqlite/table", {"File": file_name, "Table": table_name})


def EntityName(entity_ids_arr):
    return entity_ids_arr[1] + "@" + survol_sqlite.ShortenSqliteFilename(entity_ids_arr[0])


def AddInfo(grph, node, entity_ids_arr):
    fil_nam = entity_ids_arr[0]
    fil_nod = lib_uris.gUriGen.FileUri(fil_nam)
    grph.add((node, lib_common.MakeProp("File"), fil_nod))

    db_nod = sqlite_file.MakeUri(fil_nam)
    grph.add((node, lib_common.MakeProp("Sqlite database"), db_nod))
