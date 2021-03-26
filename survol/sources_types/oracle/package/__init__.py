"""
Oracle package
"""

import lib_uris
import lib_common
from lib_properties import pc

def Graphic_colorbg():
    return "#88BBFF"


def EntityOntology():
    return (["Db", "Schema", "Package"],)


# Ambiguity with tables, oracle or normal users.
def MakeUri(db_name, schema_name, package_name):
    return lib_uris.gUriGen.UriMakeFromDict(
        "oracle/package", {"Db" : db_name, "Schema": schema_name, "Package": package_name})

# Each package body has a package: This displays the package body node,
# and also the schema node.
def AddInfo(grph, node, entity_ids_arr):

    # TODO: SPECIAL. Imported here to avoid circular inclusions, see oracle/package_body/__init__.py
    from sources_types.oracle import schema as oracle_schema
    from sources_types.oracle import package_body as oracle_package_body

    arg_db = entity_ids_arr[0]
    arg_schema = entity_ids_arr[1]
    arg_package = entity_ids_arr[2]

    # TODO: PROBLEM, WHAT IF THE PACKAGE BODY DOES NOT EXIST ???
    node_package_body = oracle_package_body.MakeUri(arg_db , arg_schema, arg_package)
    grph.add((node, lib_common.MakeProp("Associated package body"), node_package_body))

    node_oraschema = oracle_schema.MakeUri(arg_db, arg_schema)
    grph.add((node_oraschema, pc.property_oracle_package, node))


def EntityName(entity_ids_arr):
    return entity_ids_arr[0] + "." + entity_ids_arr[1] + "." + entity_ids_arr[2]
