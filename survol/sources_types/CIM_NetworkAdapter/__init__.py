"""
Network adapter
"""

import lib_common


def EntityOntology():
    return (["Name"],)


def MakeUri(na_nam):
    return lib_common.gUriGen.UriMakeFromDict("CIM_NetworkAdapter", {"Name": na_nam})
