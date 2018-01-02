"""
MySql instance
"""

# This does not import mysql packages, so this will always work.
def Graphic_colorbg():
	return "#66CC00"

import lib_common

def EntityOntology():
	return ( ["Instance",], )

def MakeUri(instanceName):
	return lib_common.gUriGen.UriMakeFromDict("mysql/instance", { "Instance": instanceName } )

#def EntityName(entity_ids_arr,entity_host):
#	return entity_ids_arr[1]+ "@" + entity_ids_arr[0]

def AddInfo(grph,node,entity_ids_arr):
	instanceMySql = entity_ids_arr[0]
	instanceHost = instanceMySql.split(":")[0]
	nodeHost = lib_common.gUriGen.HostnameUri( instanceHost )
	grph.add((node,lib_common.MakeProp("Instance"),nodeHost))
