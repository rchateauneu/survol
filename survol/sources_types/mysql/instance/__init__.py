# Instances for mysql or mariadb.

"""
MySql instance
"""

import lib_common

def EntityOntology():
	return ( ["Instance",], )

def MakeUri(instanceName):
	return lib_common.gUriGen.UriMakeFromDict("mysql/instance", { "Instance": instanceName } )

#def EntityName(entity_ids_arr,entity_host):
#	return entity_ids_arr[1]+ "@" + entity_ids_arr[0]

#def AddInfo(grph,node,entity_ids_arr):
#	instanceMySql = entity_ids_arr[0]
#	nodeInstance = survol_mysql_instance.MakeUri(instanceMySql)
#	grph.add((node,lib_common.MakeProp("Instance"),nodeInstance))
