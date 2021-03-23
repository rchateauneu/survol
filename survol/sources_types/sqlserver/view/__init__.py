"""
Sqlserver view
"""

import lib_uris
import lib_common
from sources_types.sqlserver import schema as sqlserver_schema


def AddInfo(grph,node, entity_ids_arr):
    dsn_nam = entity_ids_arr[0]
    schema_nam = entity_ids_arr[1]
    node_schema = sqlserver_schema.MakeUri(dsn_nam, schema_nam)

    grph.add((node_schema, lib_common.MakeProp("sqlserver view"), node))


def EntityOntology():
    return (["Dsn", "Schema", "View"],)


# Beware of the possible confusion with normal users.
def MakeUri(dsn_nam, schema_name, view_name):
    return lib_uris.gUriGen.UriMakeFromDict("sqlserver/view", {"Dsn": dsn_nam, "Schema": schema_name, "View": view_name})


def EntityName(entity_ids_arr):
    return entity_ids_arr[0] + "." + entity_ids_arr[1] + "." + entity_ids_arr[2]
