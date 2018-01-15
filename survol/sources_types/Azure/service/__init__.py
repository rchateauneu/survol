"""
Azure service
"""

import lib_util
import lib_common

def Graphic_colorbg():
	return "#3366CC"

def EntityOntology():
	return ( ["Subscription","Service"], )

def MakeUri(serviceName, subscriptionName):
	# TODO: Because the input parameters could contain a sspace, derive from str() and define ValueDecode()
	subscriptionName = lib_util.urllib_quote(subscriptionName)
	serviceName = lib_util.urllib_quote(serviceName)
	return lib_common.gUriGen.UriMakeFromDict("Azure/service", { "Subscription" : subscriptionName, "Service" : serviceName } )

