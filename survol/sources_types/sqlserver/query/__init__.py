"""
Sqlserver query
"""

from sources_types.sql import query as sql_query
from sources_types.sqlserver import dsn as sqlserver_dsn
from sources_types.sqlserver import table as sqlserver_table
from sources_types.sqlserver import view as sqlserver_view
from sources_types import odbc as survol_odbc

import sys
import lib_util
import lib_common

# TODO: What is annoying in this model is, sometimes directories have their own ontology,
# TODO: and sometimes not. What is the rule ? There is no rule, except that: Objects
# TODO: are what is instantiated with a path of subdirectories.

# The result should be ["Query","Dsn"]
# We do not know if CIM_Process.EntityOntology() is available.
def EntityOntology():
	DEBUG("EntityOntology sql_query.CgiPropertyQuery()=%s",str(sql_query.CgiPropertyQuery()))
	DEBUG("EntityOntology survol_odbc.CgiPropertyDsn()=%s"%str(survol_odbc.CgiPropertyDsn()))
	return ( [sql_query.CgiPropertyQuery(),survol_odbc.CgiPropertyDsn()],)


# The SQL query is encoded in base 64 because it contains many special characters which would be too complicated to
# encode as HTML entities. This is not visible as EntityName() does the reverse decoding.
def MakeUri(strQuery,theDsn):
	# TODO: The right thing todo ?
	return sql_query.MakeUri( strQuery, "sqlserver/query", Dsn = theDsn )

def AddInfo(grph,node,entity_ids_arr):
	# strQuery = entity_ids_arr[0]
	theDsn = entity_ids_arr[1]
	nodeDsn = sqlserver_dsn.MakeUri(theDsn)
	grph.add((node,lib_common.MakeProp("Dsn"),nodeDsn))

# This function must have the same signature for all databases.
# For the moment, we assume that these are all table names, without checking.
# TODO: Find a quick way to check if these are tables or views.
def QueryToNodesList(sqlQuery,connectionKW,list_of_tables,defaultSchemaName=None):
	DEBUG("QueryToNodesList entering sqlQuery=%s",sqlQuery)
	nodesList = []
	if not defaultSchemaName:
		defaultSchemaName = "SqlServerDefaultSchema"
	for tabNam in list_of_tables:
		DEBUG("QueryToNodesList tabNam=%s",tabNam)
		spltTabNam = tabNam.split(".")
		if len(spltTabNam) == 2:
			schemaName = spltTabNam[0]
			tableNameNoSchema = spltTabNam[1]
		else:
			schemaName = defaultSchemaName
			tableNameNoSchema = tabNam
		DEBUG("QueryToNodesList tabNam=%s before MakeUri",tabNam)
		tmpNode = sqlserver_table.MakeUri( connectionKW["Dsn"], schemaName, tableNameNoSchema )
		DEBUG("QueryToNodesList tabNam=%s after MakeUri",tabNam)
		nodesList.append( tmpNode )
	DEBUG("QueryToNodesList leaving sqlQuery=%s",sqlQuery)
	return nodesList

# Ca fonctionne.
# EntityName = sql_query.EntityName

# Si on passait les parametres avec un dict plutot qu tableau, ce serait plus facile
# de faire appel a la "classe de base" sql/query.
def EntityName(entity_ids_arr):
	DEBUG("EntityName entity_ids_arr=%s",str(entity_ids_arr))
	sqlQuery = entity_ids_arr[0]
	dsnNam = entity_ids_arr[1]
	return sql_query.EntityNameUtil( "Database " + dsnNam,sqlQuery)
