"""
Oracle package body
"""

import lib_uris
import lib_common
from lib_properties import pc
from sources_types.oracle import schema as oracle_schema
from sources_types.oracle import package as oracle_package


def Graphic_colorbg():
    return "#CCCCCC"


def EntityOntology():
    return (["Db", "Schema", "PackageBody"],)


def MakeUri(db_name, schema_name, package_body_name):
    return lib_uris.gUriGen.node_from_dict(
        "oracle/package_body",
        {"Db": db_name, "Schema" :schema_name, "PackageBody": package_body_name})


# Each package body has a package: This displays the package node,
# and also the schema node.
def AddInfo(grph,node, entity_ids_arr):
    arg_db = entity_ids_arr[0]
    arg_schema = entity_ids_arr[1]
    arg_package_body = entity_ids_arr[2]

    node_package = oracle_package.MakeUri(arg_db , arg_schema, arg_package_body)
    grph.add((node, lib_common.MakeProp("Associated package"), node_package))

    node_oraschema = oracle_schema.MakeUri(arg_db, arg_schema)
    grph.add((node_oraschema, pc.property_oracle_package, node))


def EntityName(entity_ids_arr):
    return entity_ids_arr[0] + "." + entity_ids_arr[1] + "." + entity_ids_arr[2]
