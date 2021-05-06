"""
Oracle database table
"""

import lib_uris
import lib_common
from lib_properties import pc
from sources_types.oracle import schema as oracle_schema


def Graphic_colorbg():
    return "#66CC33"


def AddInfo(grph,node, entity_ids_arr):
    db_nam = entity_ids_arr[0]
    schema_nam = entity_ids_arr[1]
    nodeSchema = oracle_schema.MakeUri(db_nam, schema_nam)

    grph.add((nodeSchema, pc.property_oracle_table, node))


def EntityOntology():
    return (["Db", "Schema", "Table"],)


# Beware of the possible confusion with normal users.
def MakeUri(db_name, schema_name, table_name):
    return lib_uris.gUriGen.node_from_dict("oracle/table", {"Db": db_name, "Schema": schema_name, "Table": table_name})


def EntityName(entity_ids_arr):
    return entity_ids_arr[0] + "." + entity_ids_arr[1] + "." + entity_ids_arr[2]
