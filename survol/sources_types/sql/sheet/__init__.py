"""
Abstract SQL table/view
"""

import lib_uris


def EntityOntology():
    return (["Name"],)


def MakeUri(sheet_nam):
    return lib_uris.gUriGen.UriMakeFromDict("sql/sheet", {"Name": sheet_nam})

