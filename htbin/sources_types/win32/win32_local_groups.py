#!/usr/bin/python

"""
Windows local groups
"""

from __future__ import generators
import lib_util
import lib_common
from lib_common import pc

#import win32api
import win32net
#import win32netcon
import win32security
from sources_types import Win32_Group as survol_Win32_Group
from sources_types import Win32_UserAccount as survol_Win32_UserAccount

def Main():
	cgiEnv = lib_common.CgiEnv()

	if not lib_util.isPlatformWindows:
		lib_common.ErrorMessageHtml("win32 Python library only on Windows platforms")

	grph = cgiEnv.GetGraph()

	# TODO: Try this on a remote machine.
	server = None # Run on local machine.

	resume = 0
	numMembers = 0
	while True:
		level = 1
		data, total, resume = win32net.NetLocalGroupEnum(server, level, resume)
		for group in data:
			# sys.stderr.write("Group %(name)s:%(comment)s\n" % group)

			# TODO: Not sure about the groupname syntax.
			groupName = group['name']
			# nodeGroup = lib_common.gUriGen.GroupUri( groupName )
			nodeGroup = survol_Win32_Group.MakeUri( groupName, server )

			grph.add( ( nodeGroup, pc.property_host, lib_common.nodeMachine ) )
			groupComment = group['comment']
			if groupComment != "":
				groupCommentMaxWidth = max( 80, len(groupName) )
				if len(groupComment) > groupCommentMaxWidth:
					groupComment = groupComment[:groupCommentMaxWidth] + "..."
				grph.add( (nodeGroup, pc.property_information, lib_common.NodeLiteral(groupComment) ) )

			memberresume = 0
			while True:
				levelMember = 2
				memberData, total, memberResume = win32net.NetLocalGroupGetMembers(server, group['name'], levelMember, memberresume)
				for member in memberData:
					# Converts Sid to username
					userName, domain, type = win32security.LookupAccountSid(server, member['sid'])
					numMembers = numMembers + 1
					# sys.stderr.write("    Member: %s: %s\n" % (userName, member['domainandname']))
					# nodeUser = lib_common.gUriGen.UserUri( userName )
					nodeUser = survol_Win32_UserAccount.MakeUri( userName, server )

					# TODO: Not sure about the property.
					# TODO: Not sure about the username syntax.
					grph.add( (nodeUser, pc.property_group, nodeGroup ) )
				if memberResume==0:
					break
		if not resume:
			break

	cgiEnv.OutCgiRdf("LAYOUT_SPLINE")

if __name__ == '__main__':
	Main()
