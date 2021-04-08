"""
Azure service
"""

import lib_uris
import lib_util


def Graphic_colorbg():
    return "#3366CC"


def EntityOntology():
    return (["Subscription", "Service"],)


def MakeUri(service_name, subscription_name):
    subscription_name = lib_util.urllib_quote(subscription_name)
    service_name = lib_util.urllib_quote(service_name)
    return lib_uris.gUriGen.UriMakeFromDict(
        "Azure/service", {"Subscription": subscription_name, "Service": service_name})

