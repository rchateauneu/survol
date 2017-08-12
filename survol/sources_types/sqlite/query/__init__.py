"""
Sqlite query
"""

from sources_types.sql import query as sql_query
from sources_types.sqlite import table as sqlite_table
from sources_types.sqlite import file as sqlite_file
import lib_common

def Graphic_colorbg():
	return "#FFCC66"

# We do not know if CIM_Process.EntityOntology() is available.
def EntityOntology():
	return ( ["Query","File"],)

# The SQL query is encoded in base 64 because it contains many special characters which would be too complicated to
# encode as HTML entities. This is not visible as EntityName() does the reverse decoding.
def MakeUri(strQuery,fileName):
	return sql_query.MakeUri( strQuery, "sqlite/query", Path = fileName )

# TODO: Ce serait mieux de passer un dictionnaire plutot qu un tableau.
def AddInfo(grph,node,entity_ids_arr):
	fileName = entity_ids_arr[1]
	nodeFile = lib_common.gUriGen.FileUri( fileName )
	grph.add((node,lib_common.MakeProp("Path"),nodeFile))

	dbNod = sqlite_file.MakeUri( fileName )
	grph.add( ( node, lib_common.MakeProp("Sqlite database"), dbNod ) )

# It receives a query and the list of tables or views it depends on,
# and also the connection parameters to the databse, which here is only a sqlite file.
# This must return a list of nodes to be displayed, or None.
# For the moment, we assume that these are all table names, without checking.
# TODO: Find a quick way to check if these are tables or views.
def QueryToNodesList(sqlQuery,connectionKW,list_of_tables,defaultSchemaName=None):
	nodesList = []
	for tabNam in list_of_tables:
		tmpNode = sqlite_table.MakeUri( connectionKW["File"], tabNam )
		nodesList.append( tmpNode )
	return nodesList

def EntityName(entity_ids_arr,entity_host):
	sqlQuery = entity_ids_arr[0]
	fileName = entity_ids_arr[1]
	return sql_query.EntityNameUtil( "File " + fileName, sqlQuery)

