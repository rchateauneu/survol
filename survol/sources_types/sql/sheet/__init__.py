"""
Abstract SQL table/view
"""

import lib_uris


def EntityOntology():
    return (["Name"],)


def MakeUri(sheet_nam):
    return lib_uris.gUriGen.node_from_dict("sql/sheet", {"Name": sheet_nam})

