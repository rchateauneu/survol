"""
Open Database Connectivity procedure
"""

import lib_util
import lib_common

def Graphic_colorbg():
	return "#11FF11"

def EntityOntology():
	return ( ["Dsn", "Procedure"], )

def MakeUri(dsnName,procNam):
	return lib_common.gUriGen.UriMakeFromDict("odbc/procedure", { "Dsn" : lib_util.EncodeUri(dsnName), "Procedure" : procNam })
