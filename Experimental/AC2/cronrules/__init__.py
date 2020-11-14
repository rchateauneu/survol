"""
Cron rules
"""

import os
import lib_common
from sources_types import AC2

def Graphic_colorbg():
	return "#888833"

def EntityOntology():
	return ( ["File","CronId"], )

# Ambiguity with tables, oracle or normal users.
def MakeUri(configFilename,cronId):
	return lib_common.gUriGen.UriMakeFromDict("AC2/cronrules", { "File" : configFilename, "CronId":cronId } )

def EntityName(entity_ids_arr):
	return AC2.ConfigFileNameClean(entity_ids_arr[0]) + "." + entity_ids_arr[1]
