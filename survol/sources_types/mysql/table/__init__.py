# Database tables for mysql or mariadb.

"""
MySql table
"""

import lib_common

def EntityOntology():
	return ( ["Hostname","Database","Table",], )

def MakeUri(hostName,dbName,tableName):
	return lib_common.gUriGen.UriMakeFromDict("mysql/table", { "Hostname": hostName, "Database" : dbName, "Table" : tableName } )

def EntityName(entity_ids_arr,entity_host):
	return entity_ids_arr[1] + "." + entity_ids_arr[2] + "@" + entity_ids_arr[0]
