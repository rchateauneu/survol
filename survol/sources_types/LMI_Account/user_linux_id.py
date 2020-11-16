#!/usr/bin/env python

"""
Groups of a Linux user
"""

import re
import sys
import lib_common
import lib_util
from lib_properties import pc

# This runs only on Linux.
Usable = lib_util.UsableLinux


def parse_id_name(one_string):
    """Parses b"500(guest)" (bytes) and returns (500, "guest") (str)"""
    mtch = re.match(br"^([0-9]*)\(([^)]*)\)$", one_string)
    if mtch:
        return mtch.group(1), mtch.group(2).decode("utf-8")
    return -1, ""


def split_id(one_string):
    """
    This splits the line returned by the command "id".
    Maybe we could use the keys like "groups" but they depend on the locale: "groupes" ...
    "uid=500(my_user) gid=500(guest) groupes=500(guest),81(audio)"
    "uid=1001(my_user) gid=1001(my_user) groups=1001(my_user),10(wheel),993(docker) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023"
    """
    arr = one_string.split(b' ')
    resu = []
    # There should be one line only.
    for substr in arr:
        resu.append(substr.split(b'=')[1])
    return resu


def Main():
    cgiEnv = lib_common.CgiEnv()
    user_name_with_host = cgiEnv.GetId()

    # Usernames have the syntax user@host
    user_split = user_name_with_host.split('@')
    user_name = user_split[0]

    if len(user_split) > 1:
        user_host = user_split[1]
        if user_host != lib_util.currentHostname:
            # TODO: Should interrogate other host with "finger" protocol.
            lib_common.ErrorMessageHtml("Cannot get user properties on different host:" + user_host)

    if not user_name:
        lib_common.ErrorMessageHtml("Linux username should not be an empty string")

    grph = cgiEnv.GetGraph()

    user_node = lib_common.gUriGen.UserUri(user_name)

    # It runs this Linux command which returns a single line.
    id_cmd = ["id", user_name]

    id_pipe = lib_common.SubProcPOpen(id_cmd)

    (id_last_output, id_err) = id_pipe.communicate()

    lines = id_last_output.split(b'\n')
    sys.stderr.write("lines=%s\n" % lines)
    DEBUG("id=" + user_name + " lines="+str(lines))

    # $ id my_user
    # uid=500(my_user) gid=500(guest) groupes=500(guest),81(audio)

    first_line = lines[0]

    first_split = split_id(first_line)

    user_id = parse_id_name(first_split[0])[0]

    grph.add((user_node, pc.property_userid, lib_util.NodeLiteral(user_id)))

    for grp_str in first_split[2].split(b','):
        sys.stderr.write("grp_str=%s\n" % grp_str)
        group_id, group_name = parse_id_name(grp_str)
        grp_node = lib_common.gUriGen.GroupUri(group_name)
        grph.add((grp_node, pc.property_groupid, lib_util.NodeLiteral(group_id)))
        grph.add((user_node, pc.property_group, grp_node))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
