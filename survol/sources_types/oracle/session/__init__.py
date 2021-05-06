"""
Oracle session
"""

import lib_uris

def Graphic_colorbg():
    return "#FFCC66"


def EntityOntology():
    return (["Db", "Session"],)


def MakeUri(db_name, session_id):
    return lib_uris.gUriGen.node_from_dict("oracle/session", {"Db": db_name, "Session": session_id})


def EntityName(entity_ids_arr):
    return entity_ids_arr[0] + "." + entity_ids_arr[1]
