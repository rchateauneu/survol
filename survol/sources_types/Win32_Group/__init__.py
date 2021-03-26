"""
Windows group
"""

import sys

import lib_uris
import lib_util
import lib_common
from lib_properties import pc

# NetGroupEnum
# NetGroupGetInfo
# NetGroupGetUsers
# NetLocalGroupEnum

# dict = NetLocalGroupGetInfo(server, groupname , level )
# >>> win32net.NetLocalGroupGetInfo(None,"Administrators",1)
# {'comment': u'Administrators have complete and unrestricted access to the computer/domain', 'name': u'Administrators'}

# ([dict, ...], total, resumeHandle) = NetLocalGroupGetMembers(server, groupName , level , resumeHandle , prefLen )
#>>> win32net.NetLocalGroupGetMembers(None,"Administrators",2,0)
#([{'sidusage': 1L, 'domainandname': u'mymachine\\Administrator', 'sid': <PySID object at 0x00000000024C8D30>}, {'sidusage': 1L, 'domainandname': u'mymachine\\jsmith', 'sid': <PySID object at 0x00000000024C8D70>}], 2, 0)


def EntityOntology():
    return (["Name", "Domain"],)


def MakeUri(group_name, domain_name):
    if domain_name is None:
        domain_name = ""
    return lib_uris.gUriGen.UriMakeFromDict("Win32_Group", {"Name": group_name, "Domain": domain_name})


def EntityName(entity_ids_arr):
    if entity_ids_arr[1]:
        return entity_ids_arr[1] + "\\\\" + entity_ids_arr[0]
    else:
        return entity_ids_arr[0]


def AddInfo(grph, node, entity_ids_arr):
    group_name = entity_ids_arr[0]
    domain_name = entity_ids_arr[1]

    try:
        import win32net

        data_group = win32net.NetLocalGroupGetInfo(None, group_name, 1)
        comment_group = data_group['comment']
        grph.add((node, pc.property_information, lib_util.NodeLiteral(comment_group)))
    except:
        # Maybe this module cannot be imported.
        pass

    if domain_name != "NT SERVICE":
        node_machine = lib_uris.gUriGen.HostnameUri(domain_name)
        grph.add((node, lib_common.MakeProp("Host"), node_machine))
