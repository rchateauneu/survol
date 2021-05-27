"""
Open Database Connectivity table
"""

import sys

import lib_uris
from lib_properties import pc
from sources_types import odbc as survol_odbc
from sources_types.odbc import dsn as survol_odbc_dsn


def Graphic_colorbg():
    return "#66FF33"


def EntityOntology():
    return (["Dsn", "Table"],)


def MakeUri(dsn_name, table_nam):
    return lib_uris.gUriGen.node_from_dict("odbc/table", {"Dsn": dsn_name, "Table": table_nam})


def EntityName(entity_ids_arr):
    return survol_odbc.ShortenDsn(entity_ids_arr[0]) + "::" + entity_ids_arr[1]


def AddInfo(grph, node, entity_ids_arr):
    dsn_nam = entity_ids_arr[0]

    node_dsn = survol_odbc_dsn.MakeUri(dsn_nam)

    grph.add((node, pc.property_odbc_table, node_dsn))
