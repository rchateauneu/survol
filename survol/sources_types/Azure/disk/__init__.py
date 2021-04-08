"""
Azure cloud disk
"""

import lib_uris
import lib_util


def Graphic_colorbg():
    return "#FF66FF"


def EntityOntology():
    return (["Subscription", "Disk"],)


def MakeUri(disk_name, subscription_name):
    subscription_name = lib_util.urllib_quote(subscription_name)
    disk_name = lib_util.urllib_quote(disk_name)
    return lib_uris.gUriGen.UriMakeFromDict("Azure/disk", {"Subscription": subscription_name, "Disk": disk_name})

