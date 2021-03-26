"""
Oracle database
"""

import lib_uris
import lib_common


def Graphic_colorbg():
    return "#FFCC66"


def EntityOntology():
    return (["Db",],)


def MakeUri(db_name):
    return lib_uris.gUriGen.UriMakeFromDict("oracle/db", {"Db": db_name})


def EntityName(entity_ids_arr):
    return entity_ids_arr[0]

# Add a script just for the tables of the user.
# Otherwise the Oracle user needs: grant select any dictionary to <user>;
