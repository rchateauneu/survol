"""
Network adapter
"""

import lib_uris
import lib_common


def EntityOntology():
    return (["Name"],)


def MakeUri(na_nam):
    return lib_uris.gUriGen.UriMakeFromDict("CIM_NetworkAdapter", {"Name": na_nam})
