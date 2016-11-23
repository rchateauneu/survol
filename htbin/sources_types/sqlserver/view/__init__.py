import lib_common
from sources_types.sqlserver import schema as sqlserver_schema

def AddInfo(grph,node,entity_ids_arr):
	# TODO: Ca serait quand meme mieux de passer au AddInfo un dict plutot qu un tableau.
	dsnNam = entity_ids_arr[0]
	schemaNam = entity_ids_arr[1]
	nodeSchema = sqlserver_schema.MakeUri(dsnNam,schemaNam)

	grph.add( ( nodeSchema, lib_common.MakeProp("sqlserver view"), node ) )

def EntityOntology():
	return ( ["Dsn", "Schema", "View"], )

# Beware of the possible confusion with normal users.
def MakeUri(dsnNam,schemaName,viewName):
	return lib_common.gUriGen.UriMakeFromDict("sqlserver/view", { "Dsn" : dsnNam, "Schema" : schemaName, "View" : viewName } )

def EntityName(entity_ids_arr):
	return entity_ids_arr[0] + "." + entity_ids_arr[1] + "." + entity_ids_arr[2]
