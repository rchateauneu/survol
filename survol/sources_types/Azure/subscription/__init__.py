"""
Azure subscription
"""

import sys

import lib_uris
import lib_util
import lib_credentials
import lib_common


from sources_types import Azure

from azure import *
from azure.servicemanagement import *


def Graphic_colorbg():
	return "#33CC33"


def EntityOntology():
	return (["Subscription"],)


def MakeUri(subscriptionName):
	# TODO: Because the input parameters could contain a sspace, derive from str() and define ValueDecode()
	subscriptionName = lib_util.urllib_quote(subscriptionName)
	return lib_uris.gUriGen.UriMakeFromDict("Azure/subscription", { "Subscription" : subscriptionName } )


# This display extra information about a subscription.
def AddInfo(grph, node, entity_ids_arr):
	subscriptionName = entity_ids_arr[0]

	# This function is called from entity.py which does not connect to anything,
	# so we can do it here. Beware if there are too many connections,
	# because we could connect to all of them.
	try:
		subscription_id, certificate_path = lib_credentials.GetCredentials("Azure", subscriptionName)
		if not subscription_id:
			errMsg = "No credential for subscriptionName=%s" % subscriptionName
			grph.add((node, lib_common.MakeProp("Azure Error"), lib_util.NodeLiteral(errMsg)))
			return
		sms = ServiceManagementService(subscription_id, certificate_path)
	except Exception as exc:
		errMsg = "subscriptionName=%s:%s" % (subscriptionName, str(exc))
		grph.add((node, lib_common.MakeProp("Azure Error"), lib_util.NodeLiteral(errMsg)))
		return

	# There are a lot of informations
	grph.add((node, lib_common.MakeProp(".cert_file"), lib_util.NodeLiteral(sms.cert_file)))
	grph.add((node, lib_common.MakeProp(".requestid"), lib_util.NodeLiteral(sms.requestid)))
	grph.add((node, lib_common.MakeProp(".x_ms_version"), lib_util.NodeLiteral(sms.x_ms_version)))
	# grph.add( ( node, lib_common.MakeProp("Azure"), lib_util.NodeLiteral(str(dir(sms))) ) )

