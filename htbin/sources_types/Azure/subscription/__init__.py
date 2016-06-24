import sys
import rdflib
import lib_credentials
import lib_common

from sources_types import Azure
# from sources_types.Azure import subscription

from azure import *
from azure.servicemanagement import *

def MakeUri(subscriptionName):
	return lib_common.gUriGen.UriMake("Azure/subscription",subscriptionName)


# This display extra information about a subscription.
def AddInfo(grph,node,entity_ids_arr):
	subscriptionName = entity_ids_arr[0]

	# This function is called from entity.py which does not connect to anything,
	# so we can do it here. Beware if there are too many connections,
	# because we could connect to all of them.
	try:
		(subscription_id,certificate_path) = lib_credentials.GetCredentials( "Azure", subscriptionName )
		sms = ServiceManagementService(subscription_id, certificate_path)
	except:
		exc = sys.exc_info()[1]
		grph.add( ( node, lib_common.MakeProp("Error"), rdflib.Literal(str(exc)) ) )
		return

	# There are a lot of informations
	grph.add( ( node, lib_common.MakeProp(".cert_file"), rdflib.Literal(sms.cert_file)) )
	grph.add( ( node, lib_common.MakeProp(".requestid"), rdflib.Literal(sms.requestid)) )
	grph.add( ( node, lib_common.MakeProp(".x_ms_version"), rdflib.Literal(sms.x_ms_version)) )
	# grph.add( ( node, lib_common.MakeProp("Azure"), rdflib.Literal(str(dir(sms))) ) )


