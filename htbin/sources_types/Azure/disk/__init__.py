"""
Azure cloud disk
"""

import lib_common

def Graphic_colorbg():
	return "#FF66FF"

def EntityOntology():
	return ( ["Subscription","Disk"], )

def MakeUri(diskName,subscriptionName):
	return lib_common.gUriGen.UriMakeFromDict("Azure/disk", { "Subscription" : subscriptionName, "Disk" : diskName } )

