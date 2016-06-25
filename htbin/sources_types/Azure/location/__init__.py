__author__ = 'rchateau'

import lib_common

def MakeUri(locaName, subscriptionName):
	# partitionNode = lib_common.gUriGen.DiskPartitionUri( partitionNam )
	return lib_common.gUriGen.UriMake("Azure/location",locaName)

