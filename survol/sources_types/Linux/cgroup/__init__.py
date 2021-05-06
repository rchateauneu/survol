"""
Linux cgroup
"""

# No need to define Usable as we are in the Linux subdirectory.

import sys

import lib_uris


def EntityOntology():
    return (["Name"],)


def EntityName(entity_ids_arr):
    entity_id = entity_ids_arr[0]
    return entity_id


def MakeUri(cgroup_nam):
    return lib_uris.gUriGen.node_from_dict("Linux/cgroup", {"Name": cgroup_nam})
