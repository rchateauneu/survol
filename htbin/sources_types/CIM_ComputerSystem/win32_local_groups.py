#!/usr/bin/python

#import cgitb
#cgitb.enable()

from __future__ import generators
import sys
import rdflib
import lib_util
import lib_common
from lib_properties import pc

cgiEnv = lib_common.CgiEnv("Windows local groups", platform_regex = "win", can_process_remote = True)
server = cgiEnv.GetId()
if server in ["localhost","127.0.0.1"]:
	server = None

if not 'win' in sys.platform:
	lib_common.ErrorMessageHtml("win32 Python library only on Windows platforms")

try:
	import win32api
	import win32net
	import win32con
	import win32netcon
	import win32security
except ImportError:
	exc = sys.exc_info()[1]
	lib_common.ErrorMessageHtml("win32 Python library not installed:"+str(exc))

import lib_win32

grph = rdflib.Graph()

# http://www.math.uiuc.edu/~gfrancis/illimath/windows/aszgard_mini/movpy-2.0.0-py2.4.4/movpy/lib/win32/Demos/win32netdemo.py
servName_or_None, imper = lib_win32.MakeImpersonate(server)

if server == None:
	serverNode = lib_common.nodeMachine
else:
	serverNode = lib_common.gUriGen.HostnameUri(server)

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
			nodeGroup = lib_common.RemoteBox(server).GroupUri( groupName )
			grph.add( ( nodeGroup, pc.property_host, serverNode ) )
			groupComment = group['comment']
			if groupComment != "":
				groupCommentMaxWidth = max( 15, len(groupName) )
				if len(groupComment) > groupCommentMaxWidth:
					groupComment = groupComment[:groupCommentMaxWidth] + "..."
				grph.add( (nodeGroup, pc.property_information, rdflib.Literal(groupComment) ) )

			memberresume = 0
			while True:
				# memberData, total, memberResume = win32net.NetLocalGroupGetMembers(server, group['name'], 2, resume)
				memberData, total, memberResume = win32net.NetLocalGroupGetMembers(servName_or_None, group['name'], 2, resume)
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
					nodeUser = lib_common.gUriGen.UserUri( userName )
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

cgiEnv.OutCgiRdf(grph)
 
