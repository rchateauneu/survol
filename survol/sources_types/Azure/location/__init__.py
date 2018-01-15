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
	# The location might contain a space.
	subscriptionName = lib_util.urllib_quote(subscriptionName)
	locaName = lib_util.urllib_quote(locaName)
	return lib_common.gUriGen.UriMakeFromDict("Azure/location", { "Subscription" : subscriptionName, "Location" : locaName } )

