import lib_common
from lib_properties import pc
from sources_types.oracle import schema as oracle_schema
from sources_types.oracle import package as oracle_package

def EntityOntology():
	return ( ["Db", "Schema", "PackageBody"], )

def MakeUri(dbName,schemaName,packageBodyName):
	return lib_common.gUriGen.UriMakeFromDict("oracle/package_body", { "Db" : dbName, "Schema" : schemaName, "PackageBody" : packageBodyName } )

# Each package body has a package: This displays the package node,
# and also the schema node.
def AddInfo(grph,node,entity_ids_arr):
	argDb = entity_ids_arr[0]
	argSchema = entity_ids_arr[1]
	argPackageBody = entity_ids_arr[2]

	nodePackage = oracle_package.MakeUri( argDb , argSchema, argPackageBody )
	grph.add( ( node, lib_common.MakeProp("Associated package"), nodePackage ) )

	node_oraschema = oracle_schema.MakeUri( argDb, argSchema )
	grph.add( ( node_oraschema, pc.property_oracle_package, node ) )

def EntityName(entity_ids_arr,entity_host):
	return entity_ids_arr[0] + "." + entity_ids_arr[1] + "." + entity_ids_arr[2]
