#!/usr/bin/env python

# [(groupName, attribute), ...] = NetUserGetGroups(serverName, userName )
# Returns a list of groups,attributes for all groups for the user.

# >>> win32net.NetUserGetGroups(None,"jsmith")
# [(u'None', 7)]
# >>> win32net.NetUserGetGroups("TITI","vero")
# [(u'None', 7)]
# >>> win32net.NetUserGetGroups("TITI","guest")
# [(u'None', 7)]
# >>> win32net.NetUserGetGroups("TITI","guest")
# [(u'None', 7)]
# >>> win32net.NetUserGetLocalGroups("TITI","guest")
# [u'Guests']
# >>> win32net.NetUserGetLocalGroups("TITI","vero")
# [u'HomeUsers', u'Users']
# >>> win32net.NetUserGetLocalGroups(None,"jsmith")
# [u'HomeUsers', u'ORA_DBA', u'TelnetClients', u'Administrators', u'Performance Log Users']
# >>> win32net.NetUserGetGroups("Titi","rchat_000")
# [(u'None', 7)]
# >>> win32net.NetUserGetLocalGroups("Titi","rchat_000")
# [u'HomeUsers', u'Administrators', u'Performance Log Users']




"""
Groups of a Windows user
"""

import sys
import logging

import win32net

import lib_uris
import lib_util
import lib_common
from lib_properties import pc
import lib_win32

from sources_types import Win32_Group as survol_Win32_Group
from sources_types import Win32_UserAccount as survol_Win32_UserAccount

Usable = lib_util.UsableWindows

CanProcessRemote = True


def Main():
    cgiEnv = lib_common.ScriptEnvironment(can_process_remote=True)

    try:
        # Exception if local machine.
        host_name = cgiEnv.m_entity_id_dict["Domain"]
    except KeyError:
        host_name = None

    if lib_util.is_local_address(host_name):
        server_box = lib_uris.gUriGen
        serv_name_or_none = None
    else:
        server_box = lib_common.RemoteBox(host_name)
        serv_name_or_none = host_name

        try:
            lib_win32.WNetAddConnect(host_name)
        except Exception as exc:
            lib_common.ErrorMessageHtml("Error WNetAddConnect %s:%s" % (host_name, str(exc)))

    user_name = cgiEnv.m_entity_id_dict["Name"]

    logging.debug("host_name=%s user_name=%s", host_name, user_name)

    grph = cgiEnv.GetGraph()

    node_user = survol_Win32_UserAccount.MakeUri(user_name, host_name)

    # TODO: And NetUserGetGroups ??

    # [(group_name, attribute), ...] = NetUserGetGroups(serverName, user_name )
    try:
        resu_list = win32net.NetUserGetLocalGroups(serv_name_or_none, user_name)
    except Exception as exc:
        lib_common.ErrorMessageHtml("Error:user_name=" + user_name
                                + ":serv_name_or_none=" + str(serv_name_or_none) + ":" + str(exc))

    for group_name in resu_list:
        node_group = survol_Win32_Group.MakeUri(group_name, host_name)
        grph.add((node_user, pc.property_group, node_group))

        if host_name:
            node_group_remote = server_box.node_from_dict("Win32_Group", {"Name": group_name, "Domain": host_name})
            # TODO: Instead, both object must have the same universal alias
            grph.add((node_group, pc.property_alias, node_group_remote))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()


