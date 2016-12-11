#!/usr/bin/python

# [(groupName, attribute), ...] = NetUserGetGroups(serverName, userName )
# Returns a list of groups,attributes for all groups for the user.

# >>> win32net.NetUserGetGroups(None,"rchateau")
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
# >>> win32net.NetUserGetLocalGroups(None,"rchateau")
# [u'HomeUsers', u'ORA_DBA', u'TelnetClients', u'Administrators', u'Performance Log Users']
# >>> win32net.NetUserGetGroups("Titi","rchat_000")
# [(u'None', 7)]
# >>> win32net.NetUserGetLocalGroups("Titi","rchat_000")
# [u'HomeUsers', u'Administrators', u'Performance Log Users']




"""
Groups of a Windows user
"""

import sys
import rdflib
import lib_util
import lib_common
from lib_properties import pc

import win32net

from sources_types import Win32_Group as survol_Win32_Group
from sources_types import Win32_UserAccount as survol_Win32_UserAccount

# This script can work locally only.
Usable = lib_util.UsableWindows

def Main():
	cgiEnv = lib_common.CgiEnv()

	hostName = cgiEnv.m_entity_id_dict["Domain"]
	userName = cgiEnv.m_entity_id_dict["Name"]

	# if server == None:
	if hostName == None:
		serverNode = lib_common.nodeMachine
	else:
		serverNode = lib_common.gUriGen.HostnameUri(hostName)

	grph = rdflib.Graph()

	nodeUser = survol_Win32_UserAccount.MakeUri( userName, hostName )

	# [(groupName, attribute), ...] = NetUserGetGroups(serverName, userName )
	resuList = win32net.NetUserGetLocalGroups(hostName,userName)

	for groupName in resuList:
		nodeGroup = survol_Win32_Group.MakeUri( groupName, hostName )
		grph.add( ( nodeUser, pc.property_group, nodeGroup ) )

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()


