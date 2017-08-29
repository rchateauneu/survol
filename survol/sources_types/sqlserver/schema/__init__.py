import lib_common
from sources_types.sqlserver import dsn as sqlserver_dsn

def AddInfo(grph,node,entity_ids_arr):
	# TODO: Ca serait quand meme mieux de passer au AddInfo un dict plutot qu un tableau.
	dsnNam = entity_ids_arr[0]
	nodeDsn = sqlserver_dsn.MakeUri(dsnNam)

	grph.add( ( nodeDsn, lib_common.MakeProp("Sqlserver DSN"), node ) )

def EntityOntology():
	return ( [sqlserver_dsn.CgiPropertyDsn(), "Schema"], )



# Beware of the possible confusion with normal users.
def MakeUri(dsnName,schemaName):
	return lib_common.gUriGen.UriMakeFromDict("sqlserver/schema", { sqlserver_dsn.CgiPropertyDsn() : dsnName, "Schema" : schemaName } )

def EntityName(entity_ids_arr,entity_host):
	return entity_ids_arr[0] + "." + entity_ids_arr[1]

