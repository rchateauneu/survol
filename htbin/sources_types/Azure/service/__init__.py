__author__ = 'rchateau'

import lib_common

def MakeUri(serviceName, subscriptionName):
	return lib_common.gUriGen.UriMake("Azure/service",serviceName)

