"""
Oracle database view
"""

import lib_uris
import lib_common
from lib_properties import pc
from sources_types.oracle import schema as oracle_schema


def Graphic_colorbg():
    return "#FF3366"


def EntityOntology():
    return (["Db", "Schema", "View"],)


# Ambiguity with tables, oracle or normal users.
def MakeUri(db_name, schema_name, view_name):
    return lib_uris.gUriGen.node_from_dict("oracle/view", {"Db": db_name, "Schema": schema_name, "View": view_name})


def EntityName(entity_ids_arr):
    return entity_ids_arr[1] + "." + entity_ids_arr[2] + "." + entity_ids_arr[0]


def AddInfo(grph, node, entity_ids_arr):
    db_nam = entity_ids_arr[0]
    schema_nam = entity_ids_arr[1]
    node_schema = oracle_schema.MakeUri(db_nam, schema_nam)

    grph.add((node_schema, pc.property_oracle_view, node))
