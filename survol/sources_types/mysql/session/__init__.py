# Sessions  for mysql or mariadb.

"""
MySql database
"""

import lib_common
from sources_types import mysql as survol_mysql
from sources_types.mysql import instance as survol_mysql_instance

def EntityOntology():
	return ( ["Instance","Id",], )

def MakeUri(instanceName,sessionId):
	return lib_common.gUriGen.UriMakeFromDict("mysql/session", { "Instance": instanceName, "Id" sessionId } )

def EntityName(entity_ids_arr,entity_host):
	return "Session:"+entity_ids_arr[1]+ "@" + entity_ids_arr[0]

def AddInfo(grph,node,entity_ids_arr):
	instanceMySql = entity_ids_arr[0]
	nodeInstance = survol_mysql_instance.MakeUri(instanceMySql)
	grph.add((node,lib_common.MakeProp("Instance"),nodeInstance))

