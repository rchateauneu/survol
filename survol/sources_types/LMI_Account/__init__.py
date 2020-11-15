"""
Unix-like user account
"""

import sys
import lib_util
import lib_common
from lib_properties import pc


# TODO: There is an OpenLMI provider which defined the class LMI_Account.
# https://rrakus.fedorapeople.org/openlmi-account/doc/usage.html
def EntityOntology():
    return (["Name", "Domain"],)


def EntityName(entity_ids_arr):
    entity_id = entity_ids_arr[0]
    # The type of some entities can be deduced from their name.
    return entity_id


# TODO: If repetitive calls to this function, keep the result in memory.
def LoadEtcPasswd():
    """This returns a dictionary: the key is the username, and the value is the split line in /etc/passwd. """
    passwd_fil = open("/etc/passwd")
    users_dict = {}

    # polkituser:x:17:17:system user for policykit:/:/sbin/nologin
    for lin in passwd_fil:
        # sys.stderr.write("User:"+lin)
        split_lin = lin.split(':')

        # Comments might contain UTF8 accents.
        try:
            txt = split_lin[4].encode('utf-8')
        except UnicodeDecodeError as exc:
            txt = exc
        split_lin[4] = txt

        users_dict[split_lin[0]] = split_lin
    return users_dict


def AddInfo(grph, node, entity_ids_arr):
    """This must add information about the user."""
    usr_nam = entity_ids_arr[0]

    try:
        users_list = LoadEtcPasswd()
        user_split = users_list[usr_nam]
        # "postfix:x:105:109::/var/spool/postfix:/bin/false"
        usr_comment = user_split[4].strip()
        if usr_comment:
            grph.add((node, pc.property_information, lib_util.NodeLiteral(usr_comment)))

        # We insert this link to the home directory because it should not
        # imply an access to the file itself, so it cannot fail.
        home_dir = user_split[5]
        home_dir_node = lib_common.gUriGen.DirectoryUri(home_dir)

        grph.add((node, pc.property_directory, home_dir_node))

    except KeyError:
        grph.add((node, pc.property_information, lib_util.NodeLiteral( "No information available")))
