import lib_common
from lib_properties import pc

def EntityOntology():
	return ( ["Db", "Schema", "Package"], )

# Ambiguity with tables, oracle or normal users.
def MakeUri(dbName,schemaName,packageName):
	return lib_common.gUriGen.UriMakeFromDict("oracle/package", { "Db" : dbName, "Schema" : schemaName, "Package" : packageName } )

# Each package body has a package: This displays the package body node,
# and also the schema node.
def AddInfo(grph,node,entity_ids_arr):

	# TODO: SPECIAL. Imported here to avoid circular inclusions, see oracle/package_body/__init__.py
	from sources_types.oracle import schema as oracle_schema
	from sources_types.oracle import package_body as oracle_package_body

	argDb = entity_ids_arr[0]
	argSchema = entity_ids_arr[1]
	argPackage = entity_ids_arr[2]

	# TODO: PROBLEM, WHAT IF THE PACKAGE BODY DOES NOT EXIST ???
	nodePackageBody = oracle_package_body.MakeUri( argDb , argSchema, argPackage )
	grph.add( ( node, lib_common.MakeProp("Associated package body"), nodePackageBody ) )

	node_oraschema = oracle_schema.MakeUri( argDb, argSchema )
	grph.add( ( node_oraschema, pc.property_oracle_package, node ) )

def EntityName(entity_ids_arr):
	return entity_ids_arr[0] + "." + entity_ids_arr[1] + "." + entity_ids_arr[2]
