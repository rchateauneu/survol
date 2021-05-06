"""
Open Database Connectivity procedure
"""

import lib_uris
from lib_properties import pc
from sources_types import odbc as survol_odbc
from sources_types.odbc import dsn as survol_odbc_dsn


def Graphic_colorbg():
    return "#11FF11"


def EntityOntology():
    return (["Dsn", "Procedure"],)


def MakeUri(dsn_name, proc_nam):
    return lib_uris.gUriGen.node_from_dict(
        "odbc/procedure", {survol_odbc.CgiPropertyDsn(): dsn_name, "Procedure": proc_nam})


def EntityOntology():
    return ([survol_odbc.CgiPropertyDsn(), "Procedure"],)


def EntityName(entity_ids_arr):
    return survol_odbc.CgiPropertyDsn().ValueShortDisplay(entity_ids_arr[0]) + "::" + entity_ids_arr[1]


def AddInfo(grph, node, entity_ids_arr):
    dsn_nam = entity_ids_arr[0]
    node_dsn = survol_odbc_dsn.MakeUri(dsn_nam)

    grph.add((node, pc.property_odbc_procedure, node_dsn))
