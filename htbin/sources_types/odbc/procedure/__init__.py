import lib_util
import lib_common

def EntityOntology():
	return ( ["Dsn", "Procedure"], )

def MakeUri(dsnName,procNam):
	return lib_common.gUriGen.UriMakeFromDict("odbc/procedure", { "Dsn" : lib_util.EncodeUri(dsnName), "Procedure" : procNam })



