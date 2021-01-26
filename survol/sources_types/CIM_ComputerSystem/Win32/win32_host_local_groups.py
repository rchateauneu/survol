#!/usr/bin/env python

"""
Windows local groups
"""

from __future__ import generators
import sys
import logging
import lib_util
import lib_common
from lib_properties import pc

import win32net
import win32security
from sources_types import Win32_Group as survol_Win32_Group
from sources_types import Win32_UserAccount as survol_Win32_UserAccount

import lib_win32


def Main():
    cgiEnv = lib_common.CgiEnv(can_process_remote=True)
    server = cgiEnv.GetId()

    grph = cgiEnv.GetGraph()

    if lib_util.IsLocalAddress(server):
        serv_name_or_none = None
        server_node = lib_common.nodeMachine
    else:
        serv_name_or_none = server
        server_node = lib_common.gUriGen.HostnameUri(server)

    try:
        lib_win32.WNetAddConnect(serv_name_or_none)
    except Exception as exc:
        # Maybe the machine is not online.
        lib_common.ErrorMessageHtml(str(exc))

    resume = 0
    num_members = 0
    try:
        while True:
            data, total, resume = win32net.NetLocalGroupEnum(serv_name_or_none, 1, resume)
            for group in data:
                logging.debug("Group %(name)s:%(comment)s", group)

                # TODO: Not sure about the groupname syntax.
                group_name = group['name']
                logging.debug("group_name=%s", group_name)
                node_group = survol_Win32_Group.MakeUri(group_name, server)

                grph.add((node_group, pc.property_host, server_node))
                group_comment = group['comment']
                logging.debug("group_comment=%s", group_comment)
                if group_comment != "":
                    group_comment_max_width = max(80, len(group_name))
                    if len(group_comment) > group_comment_max_width:
                        group_comment = group_comment[:group_comment_max_width] + "..."
                    grph.add((node_group, pc.property_information, lib_util.NodeLiteral(group_comment)))

                memberresume = 0
                while True:
                    member_data, total, member_resume = win32net.NetLocalGroupGetMembers(serv_name_or_none,
                                                                                         group_name, 2, memberresume)
                    for member in member_data:
                        # Converts Sid to username
                        num_members = num_members + 1
                        try:
                            user_name, domain, the_type = win32security.LookupAccountSid(server, member['sid'])
                        except Exception as exc:
                            logging.warning("Server=%s LookupAccountSid Caught:%s", server, str(exc))
                            continue

                        logging.debug("Member: %s: %s server=%s", user_name, member['domainandname'], server)
                        # node_user = serverBox.UserUri( user_name )
                        node_user = survol_Win32_UserAccount.MakeUri(user_name, server)

                        # TODO: Not sure about the property.
                        # TODO: Not sure about the username syntax.
                        grph.add((node_user, pc.property_group, node_group))
                    if memberresume==0:
                        break
            if not resume:
                break
    except Exception as exc:
        lib_common.ErrorMessageHtml("win32 local groups:" + str(exc))

    cgiEnv.OutCgiRdf("LAYOUT_SPLINE")


if __name__ == '__main__':
    Main()

