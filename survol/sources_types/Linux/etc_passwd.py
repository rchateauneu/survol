#!/usr/bin/env python

"""
/etc/passwd users
"""

import sys
import lib_common
import lib_util
from lib_properties import pc
from sources_types import LMI_Account as survol_user


# TODO: https://docs.python.org/2/library/pwd.html might be simpler.
def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    grph = cgiEnv.GetGraph()

    users_dict = survol_user.LoadEtcPasswd()

    # User name
    # Information used to validate a user's password; in most modern uses.
    # user identifier number.
    # group identifier number.
    # Gecos field, commentary that describes the person or account.
    # Path to the user's home directory.
    # Program that is started every time the user logs into the system.
    #
    # polkituser:x:17:17:system user for policykit:/:/sbin/nologin
    # puppet:x:103:106:Puppet configuration management daemon,,,:/var/lib/puppet:/bin/false
    for user_nam, split_lin in users_dict.items():
        user_node = lib_common.gUriGen.UserUri(user_nam)
        comment = split_lin[4]
        # Sometimes the comment equals the user, so nothing to mention.
        if comment != "" and comment != user_nam:
            grph.add((user_node, pc.property_information, lib_util.NodeLiteral(comment)))
        home_path = split_lin[5]
        if home_path:
            if home_path == "/nonexistent":
                grph.add((user_node, pc.property_information, lib_util.NodeLiteral(home_path)))
            else:
                home_node = lib_common.gUriGen.DirectoryUri(home_path)
                grph.add((user_node, pc.property_information, home_node))
        exec_name = split_lin[6].strip()
        if exec_name:
            if exec_name == "/bin/false":
                grph.add((user_node, pc.property_information, lib_util.NodeLiteral(exec_name)))
            else:
                exec_node = lib_common.gUriGen.FileUri(exec_name)
                grph.add((user_node, pc.property_information, exec_node))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()


