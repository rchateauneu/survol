#!/usr/bin/env python

"""
Windows local group members
"""

from __future__ import generators
import sys
import lib_util
import lib_uris
import lib_common
from lib_properties import pc

import win32net
import win32security
from sources_types import Win32_Group as survol_Win32_Group
from sources_types import Win32_UserAccount as survol_Win32_UserAccount

import lib_win32

Usable = lib_util.UsableWindows

CanProcessRemote = True


def SidUsageToString(sidusage):
    try:
        return {
             1: "SidTypeUser",
             2: "SidTypeGroup",
             3: "SidTypeDomain",
             4: "SidTypeAlias",
             5: "SidTypeWellKnownGroup",
             6: "SidTypeDeletedAccount",
             7: "SidTypeInvalid",
             8: "SidTypeUnknown",
             9: "SidTypeComputer",
            10: "SidTypeLabel"
            }[int(sidusage)]
    except KeyError:
        return "Unknown SID usage:" + str(sidusage)


def _member_name_to_node(sid_usage, member_name, serv_name):
    if sid_usage == 1 or sid_usage == 6:
        member_node = survol_Win32_UserAccount.MakeUri(member_name, serv_name)
    elif sid_usage == 5 or sid_usage == 2:
        member_node = survol_Win32_Group.MakeUri(member_name, serv_name)
    else:
        serverNode = lib_common.gUriGen.HostnameUri(serv_name)
    return member_node


def _member_name_to_node_remote(sid_usage, member_name, serv_name, server_box):
    serv_name = serv_name.lower() # RFC4343
    if sid_usage == 1 or sid_usage == 6:
        member_node = server_box.UriMakeFromDict("Win32_UserAccount", {"Name": member_name, "Domain": serv_name})
    elif sid_usage == 5 or sid_usage == 2:
        member_node = server_box.UriMakeFromDict("Win32_Group", {"Name": member_name, "Domain": serv_name})
    else:
        member_node = server_box.HostnameUri(member_name)
    return member_node


def Main():
    cgiEnv = lib_common.CgiEnv(can_process_remote = True)

    server = cgiEnv.m_entity_id_dict["Domain"]
    group_name = cgiEnv.m_entity_id_dict["Name"]

    grph = cgiEnv.GetGraph()

    try:
        lib_win32.WNetAddConnect(server)
    except Exception as exc:
        lib_common.ErrorMessageHtml("Server=%s Caught:%s" % (server, str(exc)))

    if not server or lib_util.IsLocalAddress(server):
        servName_or_None = None

        # So it is compatible with WMI.
        servNameNotNone = lib_uris.TruncateHostname(lib_util.currentHostname)
        # .home
        serverNode = lib_common.nodeMachine
        serverBox = lib_common.gUriGen
    else:
        servName_or_None = server
        servNameNotNone = server
        serverNode = lib_common.gUriGen.HostnameUri(server)
        serverBox = lib_common.RemoteBox(server)

    # node_group = serverBox.GroupUri( group_name )
    # node_group = survol_Win32_Group.MakeUri( group_name, servName_or_None )
    node_group = survol_Win32_Group.MakeUri(group_name, servNameNotNone)

    try:
        memberresume = 0
        while True:
            member_data, total, member_resume = win32net.NetLocalGroupGetMembers(
                servName_or_None, group_name, 2, memberresume)

            prop_sid_usage = lib_common.MakeProp("SID Usage")
            prop_security_identifier = lib_common.MakeProp("Security Identifier")

            for member in member_data:
                sid_usage = member['sidusage']
                # Converts Sid to username
                try:
                    member_name, domain, type = win32security.LookupAccountSid(server, member['sid'])
                except Exception as exc:
                    ERROR("Server=%s Caught:%s", server, str(exc))
                    continue

                DEBUG("Member: %s:", str(member))
                DEBUG("Lookup: %s: %s", member_name, member['domainandname'])
                # nodeUser = serverBox.UserUri( userName )

                DEBUG("servNameNotNone=%s", servNameNotNone)
                member_node = _member_name_to_node(sid_usage, member_name, servNameNotNone)

                grph.add((member_node, pc.property_group, node_group))
                grph.add((member_node, prop_sid_usage, lib_util.NodeLiteral(SidUsageToString(sid_usage))))
                grph.add((member_node, prop_security_identifier, lib_util.NodeLiteral(member['sid'])))

                if servName_or_None:
                    node_member_remote = _member_name_to_node_remote(sid_usage, member_name, servName_or_None, serverBox)
                    # TODO: Instead, both object must have the same universal alias
                    grph.add((member_node, pc.property_alias, node_member_remote))

            if member_resume == 0:
                break
    except Exception as exc:
        lib_common.ErrorMessageHtml("win32 local groups:" + str(exc))

    cgiEnv.OutCgiRdf("LAYOUT_SPLINE")


if __name__ == '__main__':
    Main()
