"""
Sqlite table column
"""

import lib_common
from sources_types import sqlite as survol_sqlite

def Graphic_colorbg():
	return "#FFCC66"

def EntityOntology():
	return ( ["File","Table","Column"], )

def MakeUri(fileName,tableName,columnName):
	return lib_common.gUriGen.UriMakeFromDict("sqlite/column", { "File" : fileName, "Table" : tableName , "Column" : columnName } )

def EntityName(entity_ids_arr,entity_host):
	return entity_ids_arr[1] + "." + entity_ids_arr[2] + "@" + survol_sqlite.ShortenSqliteFilename(entity_ids_arr[0])

