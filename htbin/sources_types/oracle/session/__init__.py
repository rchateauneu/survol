import lib_common

def EntityOntology():
	return ( ["Db", "Schema", "Session"], )

def MakeUri(dbName,sessionId):
	return lib_common.gUriGen.UriMakeFromDict("oracle/session", { "Db" : dbName, "Session" : sessionId } )

def EntityName(entity_ids_arr,entity_host):
	return entity_ids_arr[0] + "." + entity_ids_arr[1]
