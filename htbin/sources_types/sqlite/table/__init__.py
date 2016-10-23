import lib_common

def EntityOntology():
	return ( ["File","Table"], )

def MakeUri(fileName,tableName):
	return lib_common.gUriGen.UriMakeFromDict("sqlite/table", { "File" : fileName, "Table" : tableName } )

def EntityName(entity_ids_arr):
	return entity_ids_arr[1] + "@" + entity_ids_arr[0]
