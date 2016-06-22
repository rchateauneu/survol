__author__ = 'rchateau'

import lib_common

def MakeUri(subscriptionName):
	return lib_common.gUriGen.UriMake("Azure/subscription",subscriptionName)

