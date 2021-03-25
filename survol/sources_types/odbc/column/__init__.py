"""
Open Database Connectivity table column
"""

import lib_util
import lib_uris
import lib_common
from sources_types import odbc as survol_odbc
from sources_types.odbc import table as odbc_table


def Graphic_colorbg():
    return "#FF6633"


def EntityOntology():
    return ([survol_odbc.CgiPropertyDsn(), "Table", "Column"],)


def MakeUri(dsn_name, table_nam, column_nam):
    return lib_uris.gUriGen.UriMakeFromDict(
        "odbc/column", {survol_odbc.CgiPropertyDsn(): dsn_name, "Table": table_nam, "Column": column_nam})


def AddInfo(grph, node, entity_ids_arr):
    dsn_nam = entity_ids_arr[0]
    tab_nam = entity_ids_arr[0]
    node_table = odbc_table.MakeUri(dsn_nam, tab_nam)
    grph.add((node_table, lib_common.MakeProp("ODBC table"), node))


def EntityName(entity_ids_arr):
    return survol_odbc.CgiPropertyDsn().ValueShortDisplay(
        entity_ids_arr[0]) + "::" + entity_ids_arr[1] + "." + entity_ids_arr[2]
