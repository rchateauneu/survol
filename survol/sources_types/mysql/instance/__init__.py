"""
MySql instance
"""

import lib_common


# This does not import mysql packages, so this will always work.
def Graphic_colorbg():
    return "#66CC00"


def EntityOntology():
    return (["Instance",],)


def MakeUri(instance_name):
    return lib_common.gUriGen.UriMakeFromDict("mysql/instance", {"Instance": instance_name})


#def EntityName(entity_ids_arr):
#    return entity_ids_arr[1]+ "@" + entity_ids_arr[0]


def AddInfo(grph,node, entity_ids_arr):
    instance_my_sql = entity_ids_arr[0]
    instance_host = instance_my_sql.split(":")[0]
    node_host = lib_common.gUriGen.HostnameUri(instance_host)
    grph.add((node, lib_common.MakeProp("Instance"), node_host))
