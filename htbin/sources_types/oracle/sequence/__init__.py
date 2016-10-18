import lib_common
from lib_properties import pc

def EntityOntology():
	return ( ["Db", "Schema", "Sequence"], )

# Ambiguity with tables, oracle or normal users.
def MakeUri(dbName,schemaName,sequenceName):
	return lib_common.gUriGen.UriMakeFromDict("oracle/sequence", { "Db" : dbName, "Schema" : schemaName, "Sequence" : sequenceName } )

def AddInfo(grph,node,entity_ids_arr):
	# TODO: SPECIAL. Imported here to avoid circular inclusions, see oracle/package_body/__init__.py
	from sources_types.oracle import schema as oracle_schema

	argDb = entity_ids_arr[0]
	argSchema = entity_ids_arr[1]

	node_oraschema = oracle_schema.MakeUri( argDb, argSchema )
	grph.add( ( node_oraschema, pc.property_oracle_sequence, node ) )
