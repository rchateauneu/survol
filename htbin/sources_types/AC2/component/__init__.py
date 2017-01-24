"""
AC2 component
"""

import lib_common
from lib_properties import pc

def EntityOntology():
	return ( ["File", "App", "Comp"], )

def MakeUri(configFilename,applicationName,componentName):
	return lib_common.gUriGen.UriMakeFromDict("AC2/component", { "File" : configFilename, "App" : applicationName, "Name" : componentName } )

def AddInfo(grph,node,entity_ids_arr):
	return

def EntityName(entity_ids_arr,entity_host):
	return entity_ids_arr[0] + "." + entity_ids_arr[1] + "." + entity_ids_arr[2]
