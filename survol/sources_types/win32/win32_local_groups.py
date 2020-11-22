#!/usr/bin/env python

"""
Windows local groups
"""

from __future__ import generators
import lib_util
import lib_uris
import lib_common
from lib_properties import pc

import win32net
import win32security
from sources_types import Win32_Group as survol_Win32_Group
from sources_types import Win32_UserAccount as survol_Win32_UserAccount


def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	# TODO: Try this on a remote machine.
	server = None # Run on local machine for the moment.

	# serv_name_or_none is for Windows functions where the local host must be None.
	# serv_name_not_none is for our URLs where the hostname must be explicit.
	if not server or lib_util.IsLocalAddress(server):
		serv_name_or_none = None

		# So it is compatible with WMI.
		serv_name_not_none = lib_uris.TruncateHostname(lib_util.currentHostname)
	else:
		serv_name_or_none = server
		serv_name_not_none = server

	resume = 0
	num_members = 0
	while True:
		level = 1
		data, total, resume = win32net.NetLocalGroupEnum(serv_name_or_none, level, resume)
		for group in data:
			# sys.stderr.write("Group %(name)s:%(comment)s\n" % group)

			# TODO: Not sure about the groupname syntax.
			group_name = group['name']
			node_group = survol_Win32_Group.MakeUri(group_name, serv_name_not_none)

			grph.add((node_group, pc.property_host, lib_common.nodeMachine))
			group_comment = group['comment']
			if group_comment != "":
				group_comment_max_width = max(80, len(group_name))
				if len(group_comment) > group_comment_max_width:
					group_comment = group_comment[:group_comment_max_width] + "..."
				grph.add((node_group, pc.property_information, lib_util.NodeLiteral(group_comment)))

			memberresume = 0
			while True:
				level_member = 2
				member_data, total, member_resume = win32net.NetLocalGroupGetMembers(
					server, group['name'], level_member, memberresume)
				for member in member_data:
					# Converts Sid to username
					userName, domain, type = win32security.LookupAccountSid(serv_name_or_none, member['sid'])
					num_members = num_members + 1
					# sys.stderr.write("    Member: %s: %s\n" % (userName, member['domainandname']))
					node_user = survol_Win32_UserAccount.MakeUri(userName, serv_name_not_none)

					# TODO: Not sure about the property.
					# TODO: Not sure about the username syntax.
					grph.add((node_user, pc.property_group, node_group))
				if memberresume == 0:
					break
		if not resume:
			break

	cgiEnv.OutCgiRdf("LAYOUT_SPLINE")


if __name__ == '__main__':
	Main()
