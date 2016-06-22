__author__ = 'rchateau'

import lib_common

def MakeUri(serviceName):
	return lib_common.gUriGen.UriMake("Azure/service",serviceName)

