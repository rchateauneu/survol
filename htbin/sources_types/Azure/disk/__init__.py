"""
Azure cloud disk
"""

import lib_common

def MakeUri(diskName,subscriptionName):
	return lib_common.gUriGen.UriMake("Azure/disk",diskName)

