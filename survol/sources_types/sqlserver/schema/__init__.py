# This is the definition of a Sql server schema.

import lib_common
import lib_uris
from sources_types.sqlserver import dsn as sqlserver_dsn


def AddInfo(grph, node, entity_ids_arr):
    dsn_nam = entity_ids_arr[0]
    node_dsn = sqlserver_dsn.MakeUri(dsn_nam)

    grph.add((node_dsn, lib_common.MakeProp("Sqlserver DSN"), node))


def EntityOntology():
    return (["Dsn", "Schema"],)


# Beware of the possible confusion with normal users.
def MakeUri(dsn_name, schema_name):
    return lib_uris.gUriGen.node_from_dict(
        "sqlserver/schema", {"Dsn": dsn_name, "Schema": schema_name})


def EntityName(entity_ids_arr):
    return entity_ids_arr[0] + "." + entity_ids_arr[1]

