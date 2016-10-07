import lib_common

# This is called by OntologyClassKeys(entity_type) when it needs the parameters f an tneity type.
def EntityOntology():
	return ( ["Dsn","SessionId"], )

def MakeUri(dsn,sessionId):
	return lib_common.gUriGen.UriMake("sqlserver/session",dsn,sessionId)