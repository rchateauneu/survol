"""
Open Database Connectivity table column
"""

import lib_util
import lib_common
from sources_types import odbc as survol_odbc
from sources_types.odbc import table as odbc_table

def Graphic_colorbg():
	return "#FF6633"

def EntityOntology():
	return ( [survol_odbc.CgiPropertyDsn(), "Table", "Column"], )

def MakeUri(dsnName,tableNam, columnNam):
	return lib_common.gUriGen.UriMakeFromDict("odbc/column", { survol_odbc.CgiPropertyDsn() : dsnName, "Table" : tableNam, "Column": columnNam })

def AddInfo(grph,node,entity_ids_arr):
	dsnNam = entity_ids_arr[0]
	tabNam = entity_ids_arr[0]
	nodeTable = odbc_table.MakeUri(dsnNam,tabNam)
	grph.add( ( nodeTable, lib_common.MakeProp("ODBC table"), node ) )


def EntityName(entity_ids_arr):
	# sys.stderr.write("EntityName entity_ids_arr=%s\n"%str(entity_ids_arr))
	return survol_odbc.CgiPropertyDsn().ValueShortDisplay(entity_ids_arr[0]) + "::" + entity_ids_arr[1] + "." + entity_ids_arr[2]
