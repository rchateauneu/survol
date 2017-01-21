"""
AC2 component
"""

import lib_common
from lib_properties import pc

def EntityOntology():
	return ( ["File", "Name"], )

# Ambiguity with tables, oracle or normal users.
def MakeUri(configFilename,componentName):
	return lib_common.gUriGen.UriMakeFromDict("AC2/component", { "File" : configFilename, "Name" : componentName } )

def AddInfo(grph,node,entity_ids_arr):
	# On ne peut guere qu afficher le script.
	# Pas d autres informations auxquelles on puisse se rattacher...
	# On peut afficher les HJOSTS et s y connecter .
	return

def EntityName(entity_ids_arr,entity_host):
	return entity_ids_arr[0] + "." + entity_ids_arr[1]
