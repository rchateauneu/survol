"""
Azure cloud location
"""

import lib_uris
import lib_util
import lib_common


def Graphic_colorbg():
    return "#FF3333"


def EntityOntology():
    return (["Subscription", "Location"],)


def MakeUri(loca_name, subscription_name):
    # TODO: Because the input parameters could contain a sspace, derive from str() and define ValueDecode()
    subscription_name = lib_util.urllib_quote(subscription_name)
    loca_name = lib_util.urllib_quote(loca_name)
    return lib_uris.gUriGen.UriMakeFromDict(
        "Azure/location", {"Subscription": subscription_name, "Location": loca_name})

