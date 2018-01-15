"""
Azure cloud location
"""

import lib_util
import lib_common

def Graphic_colorbg():
	return "#FF3333"

def EntityOntology():
	return ( ["Subscription","Location"], )

def MakeUri(locaName, subscriptionName):
	# TODO: Because the input parameters could contain a sspace, derive from str() and define ValueDecode()
	subscriptionName = lib_util.urllib_quote(subscriptionName)
	locaName = lib_util.urllib_quote(locaName)
	return lib_common.gUriGen.UriMakeFromDict("Azure/location", { "Subscription" : subscriptionName, "Location" : locaName } )

