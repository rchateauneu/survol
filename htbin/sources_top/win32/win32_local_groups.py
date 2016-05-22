#!/usr/bin/python

"""
Windows local groups
"""

from __future__ import generators
import sys
import rdflib
import lib_util
import lib_common
from lib_common import pc

import win32api
import win32net
import win32netcon
import win32security

def Main():
	cgiEnv = lib_common.CgiEnv()

	if not lib_util.isPlatformWindows:
		lib_common.ErrorMessageHtml("win32 Python library only on Windows platforms")

	grph = rdflib.Graph()

	# TODO: Try this on a remote machine.
	server = None # Run on local machine.

	resume = 0
	numMembers = 0
	while True:
		data, total, resume = win32net.NetLocalGroupEnum(server, 1, resume)
		for group in data:
			sys.stderr.write("Group %(name)s:%(comment)s\n" % group)

			# TODO: Not sure about the groupname syntax.
			groupName = group['name']
			nodeGroup = lib_common.gUriGen.GroupUri( groupName )
			grph.add( ( nodeGroup, pc.property_host, lib_common.nodeMachine ) )
			groupComment = group['comment']
			if groupComment != "":
				groupCommentMaxWidth = max( 15, len(groupName) )
				if len(groupComment) > groupCommentMaxWidth:
					groupComment = groupComment[:groupCommentMaxWidth] + "..."
				grph.add( (nodeGroup, pc.property_information, rdflib.Literal(groupComment) ) )

			memberresume = 0
			while True:
				memberData, total, memberResume = win32net.NetLocalGroupGetMembers(server, group['name'], 2, resume)
				for member in memberData:
					# Converts Sid to username
					userName, domain, type = win32security.LookupAccountSid(server, member['sid'])
					numMembers = numMembers + 1
					sys.stderr.write("    Member: %s: %s\n" % (userName, member['domainandname']))
					nodeUser = lib_common.gUriGen.UserUri( userName )
					# TODO: Not sure about the property.
					# TODO: Not sure about the username syntax.
					grph.add( (nodeUser, pc.property_group, nodeGroup ) )
				if memberResume==0:
					break
		if not resume:
			break

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()
