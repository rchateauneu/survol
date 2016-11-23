import lib_common

def EntityOntology():
	return ( ["File","View"], )

def MakeUri(fileName,viewName):
	return lib_common.gUriGen.UriMakeFromDict("sqlite/view", { "File" : fileName, "View" : viewName } )

def EntityName(entity_ids_arr):
	return entity_ids_arr[1] + "@" + entity_ids_arr[0]
