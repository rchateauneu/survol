"""
Sqlite table
"""

import lib_common
from sources_types import sqlite as survol_sqlite
from sources_types.sqlite import file as sqlite_file

def Graphic_colorbg():
	return "#FFCC66"

def EntityOntology():
	return ( ["File","Table"], )

def MakeUri(fileName,tableName):
	return lib_common.gUriGen.UriMakeFromDict("sqlite/table", { "File" : fileName, "Table" : tableName } )

def EntityName(entity_ids_arr):
	return entity_ids_arr[1] + "@" + survol_sqlite.ShortenSqliteFilename(entity_ids_arr[0])

def AddInfo(grph,node,entity_ids_arr):
	filNam = entity_ids_arr[0]
	# sys.stderr.write("AddInfo entity_id=%s\n" % pidProc )
	filNod = lib_common.gUriGen.FileUri( filNam )
	grph.add( ( node, lib_common.MakeProp("File"), filNod ) )

	dbNod = sqlite_file.MakeUri( filNam )
	grph.add( ( node, lib_common.MakeProp("Sqlite database"), dbNod ) )