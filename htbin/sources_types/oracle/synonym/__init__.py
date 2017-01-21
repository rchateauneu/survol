"""
Oracle database synonym
"""

import lib_common

def EntityOntology():
	return ( ["Db", "Schema", "Synonym"], )

# Ambiguity with tables, oracle or normal users.
def MakeUri(dbName,schemaName,synonymName):
	return lib_common.gUriGen.UriMakeFromDict("oracle/synonym", { "Db" : dbName, "Schema" : schemaName, "Synonym" : synonymName } )

def AddInfo(grph,node,entity_ids_arr):
	# TODO: SPECIAL. Imported here to avoid circular inclusions, see oracle/package_body/__init__.py
	from sources_types.oracle import schema as oracle_schema

	argDb = entity_ids_arr[0]
	argSchema = entity_ids_arr[1]

	node_oraschema = oracle_schema.MakeUri( argDb, argSchema )
	grph.add( ( node_oraschema, pc.property_oracle_synonym, node ) )

def EntityName(entity_ids_arr,entity_host):
	return entity_ids_arr[0] + "." + entity_ids_arr[1] + "." + entity_ids_arr[2]
