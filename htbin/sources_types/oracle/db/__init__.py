import lib_common

def EntityOntology():
	return ( ["Db",], )

def MakeUri(dbName):
	return lib_common.gUriGen.UriMakeFromDict("oracle/db", { "Db" : dbName } )

def EntityName(entity_ids_arr,entity_host):
	return entity_ids_arr[0]
