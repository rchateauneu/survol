import lib_util
import lib_common

def MakeUri(dsnName,procNam):
	return lib_common.gUriGen.UriMakeFromDict("odbc/procedure", { "Dsn" : lib_util.EncodeUri(dsnName), "Procedure" : procNam })



