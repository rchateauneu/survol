# Databases for mysql or mariadb.

"""
MySql instance
"""

import lib_common

def EntityOntology():
	return ( ["Instance",], )

def MakeUri(hostName,dbName):
	return lib_common.gUriGen.UriMakeFromDict("mysql/instance", { "Instance": hostName } )

def EntityName(entity_ids_arr,entity_host):
	return entity_ids_arr[1]+ "@" + entity_ids_arr[0]

def AddInfo(grph,node,entity_ids_arr):
	hostMySql = entity_ids_arr[0]
	nodeHostMySql = lib_common.gUriGen.HostnameUri( hostMySql )
	grph.add( ( node, lib_common.MakeProp("Mysql server"), nodeHostMySql ) )

