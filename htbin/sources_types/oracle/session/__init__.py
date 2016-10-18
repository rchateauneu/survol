import lib_common

def EntityOntology():
	return ( ["Db", "Schema", "Session"], )

def MakeUri(dbName,sessionId):
	return lib_common.gUriGen.UriMakeFromDict("oracle/session", { "Db" : dbName, "Session" : sessionId } )

