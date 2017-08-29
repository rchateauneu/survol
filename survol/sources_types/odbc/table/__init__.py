"""
Open Database Connectivity table
"""

import sys
import lib_util
import lib_common
from sources_types import odbc as survol_odbc

def Graphic_colorbg():
	return "#66FF33"

def EntityOntology():
	return ( [survol_odbc.CgiPropertyDsn(), "Table"], )

def MakeUri(dsnName,tableNam):
	return lib_common.gUriGen.UriMakeFromDict("odbc/table", { survol_odbc.CgiPropertyDsn() : dsnName, "Table" : tableNam })

def EntityName(entity_ids_arr,entity_host):
	# sys.stderr.write("EntityName entity_ids_arr=%s\n"%str(entity_ids_arr))
	return survol_odbc.CgiPropertyDsn().ValueShortDisplay(entity_ids_arr[0]) + "::" + entity_ids_arr[1]