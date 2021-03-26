"""
Oracle data type
"""

import lib_uris
import lib_common
from lib_properties import pc


def Graphic_colorbg():
    return "#CCCC66"


def EntityOntology():
    return (["Db", "Schema", "Type"],)


def MakeUri(db_name, schema_name, type_name):
    return lib_uris.gUriGen.UriMakeFromDict("oracle/type", {"Db": db_name, "Schema": schema_name, "Type": type_name})


def AddInfo(grph,node, entity_ids_arr):
    # TODO: SPECIAL. Imported here to avoid circular inclusions, see oracle/package_body/__init__.py
    from sources_types.oracle import schema as oracle_schema

    arg_db = entity_ids_arr[0]
    arg_schema = entity_ids_arr[1]

    node_oraschema = oracle_schema.MakeUri(arg_db, arg_schema)
    grph.add((node_oraschema, pc.property_oracle_type, node))


def EntityName(entity_ids_arr):
    return entity_ids_arr[0] + "." + entity_ids_arr[1] + "." + entity_ids_arr[2]
