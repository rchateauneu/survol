"""
AC2 trigger
"""

import os
import lib_common

from sources_types import AC2

def Graphic_colorbg():
	return "#33BB33"

def EntityOntology():
	return ( ["File","CronId","Trigger"], )

# Ambiguity with tables, oracle or normal users.
def MakeUri(configFilename,cronId,triggerName):
	return lib_common.gUriGen.UriMakeFromDict("AC2/trigger", { "File" : configFilename, "CronId":cronId,"Trigger":triggerName } )

def EntityName(entity_ids_arr,entity_host):
	return AC2.ConfigFileNameClean(entity_ids_arr[0]) + "." + entity_ids_arr[1] + "." + entity_ids_arr[2]
