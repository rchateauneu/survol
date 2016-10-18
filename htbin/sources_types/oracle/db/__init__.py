import lib_common

def EntityOntology():
	return ( ["Db",], )

def MakeUri(dbName):
	return lib_common.gUriGen.UriMakeFromDict("oracle/db", { "Db" : dbName } )
