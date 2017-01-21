"""
Sqlite file
"""

import lib_common

def EntityOntology():
	return ( ["File"], )

def MakeUri(fileName):
	return lib_common.gUriGen.UriMakeFromDict("sqlite/file", { "File" : fileName } )

def EntityName(entity_ids_arr,entity_host):
	return entity_ids_arr[0]

def AddInfo(grph,node,entity_ids_arr):
	fileName = entity_ids_arr[0]
	nodeFile = lib_common.gUriGen.FileUri( fileName )
	grph.add((node,lib_common.MakeProp("Path"),nodeFile))
