"""
Open Database Connectivity procedure
"""

import lib_util
import lib_common
from sources_types import odbc as survol_odbc

def Graphic_colorbg():
	return "#11FF11"

def EntityOntology():
	return ( ["Dsn", "Procedure"], )

def MakeUri(dsnName,procNam):
	return lib_common.gUriGen.UriMakeFromDict("odbc/procedure", { survol_odbc.CgiPropertyDsn() : dsnName, "Procedure" : procNam })

def EntityOntology():
	return ( [survol_odbc.CgiPropertyDsn(), "Procedure"], )

def EntityName(entity_ids_arr,entity_host):
	# sys.stderr.write("EntityName entity_ids_arr=%s\n"%str(entity_ids_arr))
	return survol_odbc.CgiPropertyDsn().ValueShortDisplay(entity_ids_arr[0]) + "::" + entity_ids_arr[1]