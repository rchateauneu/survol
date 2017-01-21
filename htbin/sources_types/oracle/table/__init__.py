"""
Oracle database table
"""

import lib_common
from lib_properties import pc
from sources_types.oracle import schema as oracle_schema

def AddInfo(grph,node,entity_ids_arr):
	# TODO: Ca serait quand meme mieux de passer au AddInfo un dict plutot qu un tableau.
	dbNam = entity_ids_arr[0]
	schemaNam = entity_ids_arr[1]
	nodeSchema = oracle_schema.MakeUri(dbNam,schemaNam)

	grph.add( ( nodeSchema, pc.property_oracle_table, node ) )

def EntityOntology():
	return ( ["Db", "Schema", "Table"], )

# Beware of the possible confusion with normal users.
def MakeUri(dbName,schemaName,tableName):
	return lib_common.gUriGen.UriMakeFromDict("oracle/table", { "Db" : dbName, "Schema" : schemaName, "Table" : tableName } )

def EntityName(entity_ids_arr,entity_host):
	return entity_ids_arr[0] + "." + entity_ids_arr[1] + "." + entity_ids_arr[2]
