import lib_common

def EntityOntology():
	return ( ["File","Table","Column"], )

def MakeUri(fileName,tableName,columnName):
	return lib_common.gUriGen.UriMakeFromDict("sqlite/column", { "File" : fileName, "Table" : tableName , "Column" : columnName } )

def EntityName(entity_ids_arr):
	return entity_ids_arr[1] + "." + entity_ids_arr[2] + "@" + entity_ids_arr[0]

