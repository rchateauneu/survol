"""
Sqlserver table
"""

import sys

import lib_uris
import lib_common
from sources_types.sqlserver import schema as sqlserver_schema


def AddInfo(grph,node, entity_ids_arr):
    dsn_nam = entity_ids_arr[0]
    schema_nam = entity_ids_arr[1]
    node_schema = sqlserver_schema.MakeUri(dsn_nam, schema_nam)

    grph.add((node_schema, lib_common.MakeProp("sqlserver table"), node))


def EntityOntology():
    return (["Dsn", "Schema", "Table"],)


# Beware of a possible confusion with OS users.
def MakeUri(dsn_nam, schema_name, table_name):
    return lib_uris.gUriGen.node_from_dict("sqlserver/table", {
        "Dsn": dsn_nam,
        "Schema": schema_name,
        "Table": table_name})


def EntityName(entity_ids_arr):
    return entity_ids_arr[0] + "." + entity_ids_arr[1] + "." + entity_ids_arr[2]
