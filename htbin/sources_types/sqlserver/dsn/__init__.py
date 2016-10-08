import lib_common
import lib_util


def EntityOntology():
	return ( ["Dsn"], )

def MakeUri(dsnName):
	return lib_common.gUriGen.UriMakeFromDict("sqlserver/dsn", { "Dsn" : lib_util.EncodeUri(dsnName) })
