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
import lib_util
import lib_common
from lib_properties import pc
import lib_win32

import win32net

from sources_types import Win32_Group as survol_Win32_Group
from sources_types import Win32_UserAccount as survol_Win32_UserAccount

Usable = lib_util.UsableWindows

CanProcessRemote = True

def Main():
	cgiEnv = lib_common.CgiEnv(can_process_remote = True)

	try:
		# Exception if local machine.
		hostName = cgiEnv.m_entity_id_dict["Domain"]
	except KeyError:
		hostName = None

	if not hostName or lib_util.IsLocalAddress( hostName ):
		serverBox = lib_common.gUriGen
		serverNode = lib_common.nodeMachine
		servName_or_None = None
	else:
		serverBox = lib_common.RemoteBox(hostName)
		serverNode = lib_common.gUriGen.HostnameUri(hostName)
		servName_or_None = hostName

		# hostname = "Titi" for example
		try:
			lib_win32.WNetAddConnect(hostName)
		except:
			lib_common.ErrorMessageHtml("Error WNetAddConnect %s:%s"%(hostName,str(sys.exc_info())))


	userName = cgiEnv.m_entity_id_dict["Name"]

	sys.stderr.write("hostName=%s userName=%s\n" %(hostName,userName))

	grph = cgiEnv.GetGraph()

	nodeUser = survol_Win32_UserAccount.MakeUri( userName, hostName )

	# TODO: Quid de NetUserGetGroups ??

	# [(groupName, attribute), ...] = NetUserGetGroups(serverName, userName )
	try:
		resuList = win32net.NetUserGetLocalGroups(servName_or_None,userName)
	except:
		lib_common.ErrorMessageHtml("Error:"+str(sys.exc_info()))

	for groupName in resuList:
		nodeGroup = survol_Win32_Group.MakeUri( groupName, hostName )
		grph.add( ( nodeUser, pc.property_group, nodeGroup ) )

		if hostName:
			nodeGroupRemote = serverBox.UriMakeFromDict("Win32_Group", { "Name" : groupName, "Domain" : hostName } )
			grph.add( (nodeGroup, pc.property_equivalent, nodeGroupRemote ) )



	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()


