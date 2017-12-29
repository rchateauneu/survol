"""
Linux cgroup
"""

# No need to define Usable as we are in the Linux subdirectory.

import sys
import lib_common
from lib_properties import pc

def EntityOntology():
    return ( ["Name"], )

def EntityName(entity_ids_arr,entity_host):
	entity_id = entity_ids_arr[0]
	return entity_id

def MakeUri(cgroupNam):
	return lib_common.gUriGen.UriMakeFromDict("Linux/cgroup",{ "Name":cgroupNam })
