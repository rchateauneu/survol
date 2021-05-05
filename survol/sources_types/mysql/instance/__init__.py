"""
MySql instance
"""


import lib_uris
import lib_common


# This does not import mysql packages, so this will always work.
def Graphic_colorbg():
    return "#66CC00"


def EntityOntology():
    return (["Instance",],)


def MakeUri(instance_name):
    return lib_uris.gUriGen.UriMakeFromDict("mysql/instance", {"Instance": instance_name})


def AddInfo(grph, node, entity_ids_arr):
    instance_my_sql = entity_ids_arr[0]
    instance_host = instance_my_sql.split(":")[0]
    node_host = lib_uris.gUriGen.HostnameUri(instance_host)
    grph.add((node, lib_common.MakeProp("Instance"), node_host))
