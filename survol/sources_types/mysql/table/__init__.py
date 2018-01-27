"""
MySql table
"""

import lib_common
from sources_types import mysql as survol_mysql
from sources_types.mysql import instance as survol_mysql_instance
from sources_types.mysql import database as survol_mysql_database

def EntityOntology():
	return ( ["Instance","Database","Table",], )

def MakeUri(instanceName,dbName,tableName):
	return lib_common.gUriGen.UriMakeFromDict("mysql/table", { "Instance": instanceName, "Database" : dbName, "Table" : tableName } )

def EntityName(entity_ids_arr):
	return entity_ids_arr[1] + "." + entity_ids_arr[2] + "@" + entity_ids_arr[0]

def AddInfo(grph,node,entity_ids_arr):
	instanceMySql = entity_ids_arr[0]
	databaseName = entity_ids_arr[1]
	nodeInstance = survol_mysql_instance.MakeUri(instanceMySql)
	nodeDatabase = survol_mysql_database.MakeUri(instanceMySql,databaseName)
	grph.add((node,lib_common.MakeProp("Instance"),nodeInstance))
	grph.add((node,lib_common.MakeProp("Database"),nodeDatabase))
