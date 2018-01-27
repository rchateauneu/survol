"""
Oracle database view
"""

import lib_common
from lib_properties import pc
from sources_types.oracle import schema as oracle_schema

def Graphic_colorbg():
	return "#FF3366"

def EntityOntology():
	return ( ["Db", "Schema", "View"], )

# Ambiguity with tables, oracle or normal users.
def MakeUri(dbName,schemaName,viewName):
	return lib_common.gUriGen.UriMakeFromDict("oracle/view", { "Db" : dbName, "Schema" : schemaName, "View" : viewName } )

def EntityName(entity_ids_arr):
	return entity_ids_arr[1] + "." + entity_ids_arr[2] + "." + entity_ids_arr[0]

def AddInfo(grph,node,entity_ids_arr):
	# TODO: Ca serait quand meme mieux de passer au AddInfo un dict plutot qu un tableau.
	dbNam = entity_ids_arr[0]
	schemaNam = entity_ids_arr[1]
	nodeSchema = oracle_schema.MakeUri(dbNam,schemaNam)

	grph.add( ( nodeSchema, pc.property_oracle_view, node ) )
