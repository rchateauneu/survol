"""
AC2 configuration
"""

import lib_common
from lib_properties import pc

def EntityOntology():
	return ( ["File"], )

# Ambiguity with tables, oracle or normal users.
def MakeUri(configFilename,componentName):
	return lib_common.gUriGen.UriMakeFromDict("AC2/configuration", { "File" : configFilename } )

def AddInfo(grph,node,entity_ids_arr):
	return

def EntityName(entity_ids_arr,entity_host):
	return entity_ids_arr[0] + "." + entity_ids_arr[1]