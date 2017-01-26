"""
AC2 component
"""

import os
import lib_common
from lib_properties import pc
from sources_types import AC2

def EntityOntology():
	return ( ["File", "App", "Comp"], )

def MakeUri(configFilename,applicationName,componentName):
	return lib_common.gUriGen.UriMakeFromDict("AC2/component", { "File" : configFilename, "App" : applicationName, "Comp" : componentName } )

def AddInfo(grph,node,entity_ids_arr):
	ac2File = entity_ids_arr[0]
	ac2App = entity_ids_arr[1]
	ac2Comp = entity_ids_arr[2]
	return

def EntityName(entity_ids_arr,entity_host):
	return AC2.ConfigFileNameClean(entity_ids_arr[0]) + "." + entity_ids_arr[1] + "." + entity_ids_arr[2]
