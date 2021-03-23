#!/usr/bin/env python

"""
Linux group users
"""

import sys

import lib_uris
import lib_util
import lib_common
from lib_properties import pc

Usable = lib_util.UsableLinux


def Main():
    cgiEnv = lib_common.ScriptEnvironment()
    group_name = cgiEnv.GetId()

    etc_group = open("/etc/group")

    grph = cgiEnv.GetGraph()

    split_users = []
    grp_node = lib_uris.gUriGen.GroupUri(group_name)

    grp_id = "UnknownGroup:" + group_name

    # tcpdump:x:72:
    # the_user:x:1000:the_user
    for lin_gr in etc_group:
        split_gr = lin_gr.split(':')
        try:
            if split_gr[0] == group_name:
                users_list = split_gr[3].strip()
                grp_id = split_gr[2]
                split_users = users_list.split(',')
                break
        except IndexError:
            pass

    grph.add((grp_node, pc.property_groupid, lib_util.NodeLiteral(grp_id)))

    for user_name in split_users:
        if user_name:
            user_node = lib_uris.gUriGen.UserUri(user_name)
            grph.add((user_node, pc.property_group, grp_node))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
