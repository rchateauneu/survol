"""
Azure cloud disk
"""

import lib_util
import lib_common

def Graphic_colorbg():
	return "#FF66FF"

def EntityOntology():
	return ( ["Subscription","Disk"], )

def MakeUri(diskName,subscriptionName):
	# TODO: Because the input parameters could contain a sspace, derive from str() and define ValueDecode()
	subscriptionName = lib_util.urllib_quote(subscriptionName)
	diskName = lib_util.urllib_quote(diskName)
	return lib_common.gUriGen.UriMakeFromDict("Azure/disk", { "Subscription" : subscriptionName, "Disk" : diskName } )

