"""
Oracle session
"""

import lib_common

def Graphic_colorbg():
	return "#FFCC66"

def EntityOntology():
	return ( ["Db", "Session"], )

def MakeUri(dbName,sessionId):
	return lib_common.gUriGen.UriMakeFromDict("oracle/session", { "Db" : dbName, "Session" : sessionId } )

def EntityName(entity_ids_arr):
	return entity_ids_arr[0] + "." + entity_ids_arr[1]
