"""
Open Database Connectivity table column
"""

import lib_util
import lib_common

def EntityOntology():
	return ( ["Dsn", "Table", "Column"], )

def MakeUri(dsnName,tableNam, columnNam):
	return lib_common.gUriGen.UriMakeFromDict("odbc/column", { "Dsn" : lib_util.EncodeUri(dsnName), "Table" : tableNam, "Column": columnNam })

