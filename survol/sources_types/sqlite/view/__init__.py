"""
Sqlite view
"""

import lib_common
from sources_types import sqlite as survol_sqlite

def Graphic_colorbg():
	return "#FFCC66"

def EntityOntology():
	return ( ["File","View"], )

def MakeUri(fileName,viewName):
	return lib_common.gUriGen.UriMakeFromDict("sqlite/view", { "File" : fileName, "View" : viewName } )

def EntityName(entity_ids_arr):
	return entity_ids_arr[1] + "@" + survol_sqlite.ShortenSqliteFilename(entity_ids_arr[0])
