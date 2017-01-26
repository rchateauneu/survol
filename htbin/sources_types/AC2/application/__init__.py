"""
AC2 application
"""

import lib_common
from lib_properties import pc
from sources_types import AC2

def EntityOntology():
	return ( ["File", "App"], )

def MakeUri(configFilename,applicationName):
	return lib_common.gUriGen.UriMakeFromDict("AC2/application", { "File" : configFilename, "App" : applicationName } )

def AddInfo(grph,node,entity_ids_arr):
	return

def EntityName(entity_ids_arr,entity_host):
	return AC2.ConfigFileNameClean(entity_ids_arr[0]) + "." + entity_ids_arr[1]
