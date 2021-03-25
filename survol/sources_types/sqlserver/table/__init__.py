"""
Sqlserver table
"""

import sys

import lib_uris
import lib_common
from sources_types.sqlserver  import dsn as sqlserver_dsn
from sources_types.sqlserver import schema as sqlserver_schema


def AddInfo(grph,node, entity_ids_arr):
    dsn_nam = entity_ids_arr[0]
    schema_nam = entity_ids_arr[1]
    node_schema = sqlserver_schema.MakeUri(dsn_nam,schema_nam)

    grph.add((node_schema, lib_common.MakeProp("sqlserver table"), node))


def EntityOntology():
    return ([sqlserver_dsn.CgiPropertyDsn(), "Schema", "Table"],)


# Beware of the possible confusion with normal users.
def MakeUri(dsn_nam, schema_name, table_name):
    # sys.stderr.write("sqlserver/table tableName=%s\n"%tableName)
    return lib_uris.gUriGen.UriMakeFromDict("sqlserver/table", {
        sqlserver_dsn.CgiPropertyDsn(): dsn_nam,
        "Schema": schema_name,
        "Table": table_name})


def EntityName(entity_ids_arr):
    return entity_ids_arr[0] + "." + entity_ids_arr[1] + "." + entity_ids_arr[2]
