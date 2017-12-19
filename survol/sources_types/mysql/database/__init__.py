# Databases for mysql or mariadb.

"""
MySql database
"""

import lib_common
from sources_types import mysql as survol_mysql
from sources_types.mysql import instance as survol_mysql_instance

def EntityOntology():
	return ( ["Instance","Database",], )

def MakeUri(instanceName,dbName):
	return lib_common.gUriGen.UriMakeFromDict("mysql/database", { "Instance": instanceName, "Database" : dbName } )

def EntityName(entity_ids_arr,entity_host):
	return entity_ids_arr[1]+ "@" + entity_ids_arr[0]

def AddInfo(grph,node,entity_ids_arr):
	instanceMySql = entity_ids_arr[0]
	nodeInstance = survol_mysql_instance.MakeUri(instanceMySql)
	grph.add((node,lib_common.MakeProp("Instance"),nodeInstance))

