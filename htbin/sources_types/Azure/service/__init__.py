"""
Azure service
"""

import lib_common

def EntityOntology():
	return ( ["Subscription","Service"], )

def MakeUri(serviceName, subscriptionName):
	return lib_common.gUriGen.UriMakeFromDict("Azure/service", { "Subscription" : subscriptionName, "Service" : serviceName } )

