"""
Azure subscription
"""

import sys

from azure import *
from azure.servicemanagement import *

import lib_uris
import lib_util
import lib_credentials
import lib_common
from sources_types import Azure


def Graphic_colorbg():
    return "#33CC33"


def EntityOntology():
    return (["Subscription"],)


def MakeUri(subscription_name):
    subscription_name = lib_util.urllib_quote(subscription_name)
    return lib_uris.gUriGen.UriMakeFromDict("Azure/subscription", {"Subscription" : subscription_name})


# This display extra information about a subscription.
def AddInfo(grph, node, entity_ids_arr):
    subscription_name = entity_ids_arr[0]

    # This function is called from entity.py which does not connect to anything,
    # so we can do it here. Beware if there are too many connections,
    # because we could connect to all of them.
    try:
        subscription_id, certificate_path = lib_credentials.GetCredentials("Azure", subscription_name)
        if not subscription_id:
            err_msg = "No credential for subscription_name=%s" % subscription_name
            grph.add((node, lib_common.MakeProp("Azure Error"), lib_util.NodeLiteral(err_msg)))
            return
        sms = ServiceManagementService(subscription_id, certificate_path)
    except Exception as exc:
        err_msg = "subscription_name=%s:%s" % (subscription_name, str(exc))
        grph.add((node, lib_common.MakeProp("Azure Error"), lib_util.NodeLiteral(err_msg)))
        return

    # There are a lot of informations
    grph.add((node, lib_common.MakeProp(".cert_file"), lib_util.NodeLiteral(sms.cert_file)))
    grph.add((node, lib_common.MakeProp(".requestid"), lib_util.NodeLiteral(sms.requestid)))
    grph.add((node, lib_common.MakeProp(".x_ms_version"), lib_util.NodeLiteral(sms.x_ms_version)))
    # grph.add( ( node, lib_common.MakeProp("Azure"), lib_util.NodeLiteral(str(dir(sms))) ) )

