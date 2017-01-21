"""
Oracle database query
"""

from sources_types.sql import query as sql_query
from sources_types.oracle import db as oracle_db
from sources_types.oracle import table as oracle_table
from sources_types.oracle import view as oracle_view
from sources_types.oracle import synonym as oracle_synonym
import lib_util
import lib_common
import sys

# TODO: What is annoying in this model is, sometimes directories have their own ontology,
# TODO: and sometimes not. What is the rule ? There is no rule, except that: Objects
# TODO: are what is instantiated with a path of subdirectories.

# The result should be ["Query","Db"]
# We do not know if CIM_Process.EntityOntology() is available.
def EntityOntology():
	# return sql_query.EntityOntology() + lib_util.OntologyClassKeys("oracle/db")
	# return ( ["Db","Query"],)
	return ( ["Query","Db"],)

# The SQL query is encoded in base 64 because it contains many special characters which would be too complicated to
# encode as HTML entities. This is not visible as EntityName() does the reverse decoding.
def MakeUri(strQuery,theDb):
	#strQueryEncoded = lib_util.Base64Encode(strQuery)
	# TODO: We have hard-coded the process definition with "Db".
	# TODO: The entity parameter should be passed differently, more elegant. Not sure.
	#return lib_common.gUriGen.UriMakeFromDict("sql/query",{ "Query" : strQueryEncoded, "Handle" : thePid })
	return sql_query.MakeUri( strQuery, "oracle/query", Db = theDb )

# TODO: Ce serait mieux de passer un dictionnaire plutot qu un tableau.
def AddInfo(grph,node,entity_ids_arr):
	theDb = entity_ids_arr[1]
	nodeDb = oracle_db.MakeUri(theDb)
	grph.add((node,lib_common.MakeProp("Db"),nodeDb))

# For the moment, we assume that these are all table names, without checking.
# TODO: Find a quick way to check if these are tables or views.
def QueryToNodesList(sqlQuery,connectionKW,list_of_tables):
	nodesList = []
	# This should be taken from the credentials.
	defaultSchemaName = "OracleSchema"
	for tabNam in list_of_tables:
		spltTabNam = tabNam.split(".")
		if len(spltTabNam) == 2:
			schemaName = spltTabNam[0]
			tableNameNoSchema = spltTabNam[1]
		else:
			schemaName = defaultSchemaName
			tableNameNoSchema = tabNam
		tmpNode = oracle_table.MakeUri( connectionKW["Db"], schemaName, tableNameNoSchema )
		nodesList.append( tmpNode )
	return nodesList

def EntityName(entity_ids_arr,entity_host):
	sqlQuery = entity_ids_arr[0]
	dbNam = entity_ids_arr[1]
	return sql_query.EntityNameUtil( "Database " + dbNam,sqlQuery)
