"""
Scripts related to Windows Win32_UserAccount class.
"""
import lib_common
import lib_uris


def EntityOntology():
    return (["Name", "Domain"],)


# BEWARE: Very close to lib_uris.UserUri
def MakeUri(user_name, domain_name):
    domain_name = domain_name.lower()
    return lib_uris.gUriGen.node_from_dict("Win32_UserAccount", {"Name": user_name, "Domain": domain_name})


def EntityName(entity_ids_arr):
    if entity_ids_arr[1]:
        return entity_ids_arr[1] + "\\\\" + entity_ids_arr[0]
    else:
        return entity_ids_arr[0]


def AddInfo(grph, node, entity_ids_arr):
    # group_name = entity_ids_arr[0]
    domain_name = entity_ids_arr[1]
    node_machine = lib_uris.gUriGen.HostnameUri(domain_name)
    grph.add((node, lib_uris.MakeProp("Host"), node_machine))