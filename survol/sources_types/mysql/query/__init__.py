"""
Mysql query
"""

from sources_types.sql import query as sql_query

from sources_types.mysql import table as mysql_table
from sources_types import mysql as survol_mysql
from sources_types.mysql import instance as survol_mysql_instance

import lib_common

# We do not know if CIM_Process.EntityOntology() is available.
def EntityOntology():
	return ( ["Instance",],)

# The SQL query is encoded in base 64 because it contains many special characters which would be too complicated to
# encode as HTML entities. This is not visible as EntityName() does the reverse decoding.
def MakeUri(strQuery,instanceName):
	return sql_query.MakeUri( strQuery, "mysql/query", Instance = instanceName )

# TODO: Ce serait mieux de passer un dictionnaire plutot qu un tableau.
def AddInfo(grph,node,entity_ids_arr):
	instanceName = entity_ids_arr[1]
	nodeInstance = survol_mysql_instance.MakeUri(instanceName)
	grph.add((node,lib_common.MakeProp("Instance"),nodeInstance))

# It receives a query and the list of tables or views it depends on,
# and also the connection parameters to the database, which here is only a mysql instance,
# which is a host name, or a host followed by the port number, separated by a colon:
# This must return a list of nodes to be displayed, or None.
# For the moment, we assume that these are all table names, without checking.
# TODO: Find a quick way to check if these are tables or views.
def QueryToNodesList(sqlQuery,connectionKW,list_of_tables,defaultSchemaName=None):
	nodesList = []
	for tabNam in list_of_tables:
		tmpNode = sqlite_table.MakeUri( connectionKW["Instance"], tabNam )
		nodesList.append( tmpNode )
	return nodesList

def EntityName(entity_ids_arr,entity_host):
	sqlQuery = entity_ids_arr[0]
	instanceName = entity_ids_arr[1]
	return sql_query.EntityNameUtil( "Instance " + instanceName, sqlQuery)

