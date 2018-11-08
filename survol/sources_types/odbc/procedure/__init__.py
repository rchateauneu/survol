"""
Open Database Connectivity procedure
"""

import lib_util
import lib_common
from lib_properties import pc
from sources_types import odbc as survol_odbc
from sources_types.odbc import dsn as survol_odbc_dsn

def Graphic_colorbg():
	return "#11FF11"

def EntityOntology():
	return ( ["Dsn", "Procedure"], )

def MakeUri(dsnName,procNam):
	return lib_common.gUriGen.UriMakeFromDict("odbc/procedure", { survol_odbc.CgiPropertyDsn() : dsnName, "Procedure" : procNam })

def EntityOntology():
	return ( [survol_odbc.CgiPropertyDsn(), "Procedure"], )

def EntityName(entity_ids_arr):
	# sys.stderr.write("EntityName entity_ids_arr=%s\n"%str(entity_ids_arr))
	return survol_odbc.CgiPropertyDsn().ValueShortDisplay(entity_ids_arr[0]) + "::" + entity_ids_arr[1]

def AddInfo(grph,node,entity_ids_arr):
	dsnNam = entity_ids_arr[0]
	# procNam = entity_ids_arr[1]
	nodeDsn = survol_odbc_dsn.MakeUri( dsnNam )

	grph.add((node,pc.property_odbc_procedure, nodeDsn))

