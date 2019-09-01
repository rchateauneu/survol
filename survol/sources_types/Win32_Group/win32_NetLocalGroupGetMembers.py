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
			 1 : "SidTypeUser",
			 2 : "SidTypeGroup",
			 3 : "SidTypeDomain",
			 4 : "SidTypeAlias",
			 5 : "SidTypeWellKnownGroup",
			 6 : "SidTypeDeletedAccount",
			 7 : "SidTypeInvalid",
			 8 : "SidTypeUnknown",
			 9 : "SidTypeComputer",
			10 : "SidTypeLabel"
			}[int(sidusage)]
	except KeyError:
		return "Unknown SID usage:" + str(sidusage)

def MemberNameToNode(sidUsage,memberName,servName):
	if sidUsage == 1 or sidUsage == 6:
		memberNode = survol_Win32_UserAccount.MakeUri( memberName, servName )
	elif sidUsage == 5 or sidUsage == 2:
		memberNode = survol_Win32_Group.MakeUri( memberName, servName )
	else:
		serverNode = lib_common.gUriGen.HostnameUri(servName)
	return memberNode

def MemberNameToNodeRemote(sidUsage,memberName,servName,serverBox):
	servName = servName.lower() # RFC4343
	if sidUsage == 1 or sidUsage == 6:
		memberNode = serverBox.UriMakeFromDict("Win32_UserAccount", { "Name" : memberName, "Domain" : servName } )
	elif sidUsage == 5 or sidUsage == 2:
		memberNode = serverBox.UriMakeFromDict("Win32_Group", { "Name" : memberName, "Domain" : servName } )
	else:
		memberNode = serverBox.HostnameUri(memberName)
	return memberNode


def Main():
	cgiEnv = lib_common.CgiEnv(can_process_remote = True)

	server = cgiEnv.m_entity_id_dict["Domain"]
	groupName = cgiEnv.m_entity_id_dict["Name"]

	grph = cgiEnv.GetGraph()

	# http://www.math.uiuc.edu/~gfrancis/illimath/windows/aszgard_mini/movpy-2.0.0-py2.4.4/movpy/lib/win32/Demos/win32netdemo.py

	# hostname = "Titi" for example
	try:
		lib_win32.WNetAddConnect(server)
	except:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Server=%s Caught:%s" % ( server, str(exc) ) )

	if not server or lib_util.IsLocalAddress( server ):
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

	# nodeGroup = serverBox.GroupUri( groupName )
	# nodeGroup = survol_Win32_Group.MakeUri( groupName, servName_or_None )
	nodeGroup = survol_Win32_Group.MakeUri( groupName, servNameNotNone )

	try:
		memberresume = 0
		while True:
			memberData, total, memberResume = win32net.NetLocalGroupGetMembers(servName_or_None, groupName, 2, memberresume)
			for member in memberData:
				sidUsage = member['sidusage']
				# Converts Sid to username
				try:
					memberName, domain, type = win32security.LookupAccountSid(server, member['sid'])
				except Exception:
					exc = sys.exc_info()[1]
					ERROR("Server=%s Caught:%s", server, str(exc) )
					continue

				DEBUG("Member: %s:", str(member))
				DEBUG("Lookup: %s: %s", memberName, member['domainandname'])
				# nodeUser = serverBox.UserUri( userName )

				DEBUG("servNameNotNone=%s",servNameNotNone)
				memberNode = MemberNameToNode(sidUsage,memberName,servNameNotNone)

				grph.add( (memberNode, pc.property_group, nodeGroup ) )
				grph.add( (memberNode, lib_common.MakeProp("SID Usage"), lib_common.NodeLiteral(SidUsageToString(sidUsage) ) ) )
				grph.add( (memberNode, lib_common.MakeProp("Security Identifier"), lib_common.NodeLiteral(member['sid']) ) )

				if servName_or_None:
					nodeMemberRemote = MemberNameToNodeRemote(sidUsage,memberName,servName_or_None,serverBox)
					# TODO: Instead, both object must have the same universal alias
					grph.add( (memberNode, pc.property_alias, nodeMemberRemote ) )



			if memberResume==0:
				break
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("win32 local groups:"+str(exc))

	cgiEnv.OutCgiRdf("LAYOUT_SPLINE")

if __name__ == '__main__':
	Main()
