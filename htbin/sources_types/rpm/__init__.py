#import os
#import sys
#import lib_uris
import lib_common

def EntityOntology():
	return ( ["Rpm",], )

def MakeUri(rpmName):
	return lib_common.gUriGen.UriMakeFromDict("rpm", { "Rpm" : rpmName } )

def EntityName(entity_ids_arr):
	return entity_ids_arr[0]
