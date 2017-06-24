#!/usr/bin/python

"""
Windows local groups
"""

from __future__ import generators
import sys
import lib_util
import lib_common
from lib_properties import pc

#import win32api
import win32net
#import win32con
#import win32netcon
import win32security
from sources_types import Win32_Group as survol_Win32_Group
from sources_types import Win32_UserAccount as survol_Win32_UserAccount

import lib_win32

Usable = lib_util.UsableWindows

def Main():
	cgiEnv = lib_common.CgiEnv(can_process_remote = True)
	server = cgiEnv.GetId()

	if lib_util.IsLocalAddress( server ):
		server = None

	grph = cgiEnv.GetGraph()

	# http://www.math.uiuc.edu/~gfrancis/illimath/windows/aszgard_mini/movpy-2.0.0-py2.4.4/movpy/lib/win32/Demos/win32netdemo.py
	# servName_or_None, imper = lib_win32.MakeImpersonate(server)

	# hostname = "Titi" for example
	try:
		lib_win32.WNetAddConnect(server)
	except:
		# Maybe the machine is not online.
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml(str(exc))

	# It might be an empty string.
	if server:
		servName_or_None = server
	else:
		servName_or_None = None

	if servName_or_None:
		serverNode = lib_common.gUriGen.HostnameUri(server)
		serverBox = lib_common.RemoteBox(server)
	else:
		serverNode = lib_common.nodeMachine
		serverBox = lib_common.gUriGen

	resume = 0
	numMembers = 0
	try:
		while True:
			# data, total, resume = win32net.NetLocalGroupEnum(server, 1, resume)
			data, total, resume = win32net.NetLocalGroupEnum(servName_or_None, 1, resume)
			for group in data:
				sys.stderr.write("Group %(name)s:%(comment)s\n" % group)

				# TODO: Not sure about the groupname syntax.
				groupName = group['name']
				sys.stderr.write("groupName=%s\n" % groupName)
				# nodeGroup = serverBox.GroupUri( groupName )
				nodeGroup = survol_Win32_Group.MakeUri( groupName, servName_or_None )

				grph.add( ( nodeGroup, pc.property_host, serverNode ) )
				groupComment = group['comment']
				sys.stderr.write("groupComment=%s\n" % groupComment)
				if groupComment != "":
					groupCommentMaxWidth = max( 80, len(groupName) )
					if len(groupComment) > groupCommentMaxWidth:
						groupComment = groupComment[:groupCommentMaxWidth] + "..."
					grph.add( (nodeGroup, pc.property_information, lib_common.NodeLiteral(groupComment) ) )

				memberresume = 0
				while True:
					# memberData, total, memberResume = win32net.NetLocalGroupGetMembers(server, group['name'], 2, resume)
					memberData, total, memberResume = win32net.NetLocalGroupGetMembers(servName_or_None, group['name'], 2, memberresume)
					for member in memberData:
						# Converts Sid to username
						numMembers = numMembers + 1
						try:
							userName, domain, type = win32security.LookupAccountSid(server, member['sid'])
						except Exception:
							exc = sys.exc_info()[1]
							sys.stderr.write("Server=%s Caught:%s\n" % ( server, str(exc) ) )
							continue

						sys.stderr.write("    Member: %s: %s\n" % (userName, member['domainandname']))
						# nodeUser = serverBox.UserUri( userName )
						nodeUser = survol_Win32_UserAccount.MakeUri( userName, servName_or_None )

						# TODO: Not sure about the property.
						# TODO: Not sure about the username syntax.
						grph.add( (nodeUser, pc.property_group, nodeGroup ) )
					if memberResume==0:
						break
			if not resume:
				break
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("win32 local groups:"+str(exc))

	cgiEnv.OutCgiRdf("LAYOUT_SPLINE")
 
if __name__ == '__main__':
	Main()



# >>> win32net.NetLocalGroupEnum(None,1)
# ([{'comment': u'Administrators have complete and unrestricted access to the computer/domain', 'name': u'Administrators'}, {'comment'
# : u'Backup Operators can override security restrictions for the sole purpose of backing up or restoring files', 'name': u'Backup Ope
# rators'}, {'comment': u'Members are authorized to perform cryptographic operations.', 'name': u'Cryptographic Operators'}, {'comment
# ': u'Members are allowed to launch, activate and use Distributed COM objects on this machine.', 'name': u'Distributed COM Users'}, {
# 'comment': u'Members of this group can read event logs from local machine', 'name': u'Event Log Readers'}, {'comment': u'Guests have
#  the same access as members of the Users group by default, except for the Guest account which is further restricted', 'name': u'Gues
# ts'}, {'comment': u'Built-in group used by Internet Information Services.', 'name': u'IIS_IUSRS'}, {'comment': u'Members in this gro
# up can have some administrative privileges to manage configuration of networking features', 'name': u'Network Configuration Operator
# s'}, {'comment': u'Members of this group may schedule logging of performance counters, enable trace providers, and collect event tra
# ces both locally and via remote access to this computer', 'name': u'Performance Log Users'}, {'comment': u'Members of this group can
#  access performance counter data locally and remotely', 'name': u'Performance Monitor Users'}, {'comment': u'Power Users are include
# d for backwards compatibility and possess limited administrative powers', 'name': u'Power Users'}, {'comment': u'Members in this gro
# up are granted the right to logon remotely', 'name': u'Remote Desktop Users'}, {'comment': u'Supports file replication in a domain',
#  'name': u'Replicator'}, {'comment': u'Users are prevented from making accidental or intentional system-wide changes and can run mos
# t applications', 'name': u'Users'}, {'comment': u'Utilized by HP Device Access Manager to control access to devices.', 'name': u'Dev
# ice Administrators'}, {'comment': u'', 'name': u'HelpLibraryUpdaters'}, {'comment': u'HomeUsers Security Group', 'name': u'HomeUsers
# '}, {'comment': u'Oracle DBA Group', 'name': u'ORA_DBA'}, {'comment': u'Members in the group have the required access and privileges
#  to be assigned as the log on account for the associated instance of SQL Server Browser.', 'name': u'SQLServer2005SQLBrowserUser$RCH
# ATEAU-HP'}, {'comment': u'', 'name': u'TelnetClients'}], 20, 0)
# >>>
# >>>
# >>> win32net.NetGroupEnum(None,1)
# ([{'comment': u'Ordinary users', 'name': u'None'}], 1, 0)
# >>>
# >>> win32net.NetLocalGroupEnum("Titi",1)
# ([{'comment': u'Administrators have complete and unrestricted access to the computer/domain', 'name': u'Administrators'}, {'comment'
# : u'Members are allowed to launch, activate and use Distributed COM objects on this machine.', 'name': u'Distributed COM Users'}, {'
# comment': u'Members of this group can read event logs from local machine', 'name': u'Event Log Readers'}, {'comment': u'Guests have
# the same access as members of the Users group by default, except for the Guest account which is further restricted', 'name': u'Guest
# s'}, {'comment': u'Built-in group used by Internet Information Services.', 'name': u'IIS_IUSRS'}, {'comment': u'Members of this grou
# p may schedule logging of performance counters, enable trace providers, and collect event traces both locally and via remote access
# to this computer', 'name': u'Performance Log Users'}, {'comment': u'Members of this group can access performance counter data locall
# y and remotely', 'name': u'Performance Monitor Users'}, {'comment': u'Members of this group can access WMI resources over management
#  protocols (such as WS-Management via the Windows Remote Management service). This applies only to WMI namespaces that grant access
# to the user.', 'name': u'Remote Management Users'}, {'comment': u'Users are prevented from making accidental or intentional system-w
# ide changes and can run most applications', 'name': u'Users'}, {'comment': u'HomeUsers Security Group', 'name': u'HomeUsers'}, {'com
# ment': u'Members in the group have the required access and privileges to be assigned as the log on account for the associated instan
# ce of SQL Server Browser.', 'name': u'SQLServer2005SQLBrowserUser$TITI'}, {'comment': u'', 'name': u'TelnetClients'}, {'comment': u'
# Members of this group can access WMI resources over management protocols (such as WS-Management via the Windows Remote Management se
# rvice). This applies only to WMI namespaces that grant access to the user.', 'name': u'WinRMRemoteWMIUsers__'}], 13, 0)
# >>>
# >>>
# >>> win32net.NetGroupEnum("Titi",1)
# ([{'comment': u'Ordinary users', 'name': u'None'}], 1, 0)
#
