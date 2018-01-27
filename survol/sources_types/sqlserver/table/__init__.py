"""
Sqlserver table
"""

import sys
import lib_common
from sources_types.sqlserver  import dsn as sqlserver_dsn
from sources_types.sqlserver import schema as sqlserver_schema

def AddInfo(grph,node,entity_ids_arr):
	# TODO: Ca serait quand meme mieux de passer au AddInfo un dict plutot qu un tableau.
	dsnNam = entity_ids_arr[0]
	schemaNam = entity_ids_arr[1]
	nodeSchema = sqlserver_schema.MakeUri(dsnNam,schemaNam)

	grph.add( ( nodeSchema, lib_common.MakeProp("sqlserver table"), node ) )

def EntityOntology():
	return ( [sqlserver_dsn.CgiPropertyDsn(), "Schema", "Table"], )

# Beware of the possible confusion with normal users.
def MakeUri(dsnNam,schemaName,tableName):
	# sys.stderr.write("sqlserver/table tableName=%s\n"%tableName)
	return lib_common.gUriGen.UriMakeFromDict("sqlserver/table", { sqlserver_dsn.CgiPropertyDsn() : dsnNam, "Schema" : schemaName, "Table" : tableName } )

def EntityName(entity_ids_arr):
	return entity_ids_arr[0] + "." + entity_ids_arr[1] + "." + entity_ids_arr[2]
