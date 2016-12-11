#!/usr/bin/python

"""
Members of a Windows local group
"""

from __future__ import generators
import sys
import rdflib
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

	server = cgiEnv.m_entity_id_dict["Domain"]
	groupName = cgiEnv.m_entity_id_dict["Name"]

	if lib_util.IsLocalAddress( server ):
		server = None

	grph = rdflib.Graph()

	# http://www.math.uiuc.edu/~gfrancis/illimath/windows/aszgard_mini/movpy-2.0.0-py2.4.4/movpy/lib/win32/Demos/win32netdemo.py
	servName_or_None, imper = lib_win32.MakeImpersonate(server)

	# if server == None:
	if servName_or_None == None:
		serverNode = lib_common.nodeMachine
		serverBox = lib_common.gUriGen
	else:
		serverNode = lib_common.gUriGen.HostnameUri(server)
		serverBox = lib_common.RemoteBox(server)

	# nodeGroup = serverBox.GroupUri( groupName )
	nodeGroup = survol_Win32_Group.MakeUri( groupName, servName_or_None )

	try:
		memberresume = 0
		while True:
			memberData, total, memberResume = win32net.NetLocalGroupGetMembers(servName_or_None, groupName, 2, memberresume)
			for member in memberData:
				# Converts Sid to username
				try:
					userName, domain, type = win32security.LookupAccountSid(server, member['sid'])
				except Exception:
					exc = sys.exc_info()[1]
					sys.stderr.write("Server=%s Caught:%s\n" % ( server, str(exc) ) )
					continue

				sys.stderr.write("    Member: %s: %s\n" % (userName, member['domainandname']))
				# nodeUser = serverBox.UserUri( userName )
				nodeUser = survol_Win32_UserAccount.MakeUri( userName, servName_or_None )

				grph.add( (nodeUser, pc.property_group, nodeGroup ) )
			if memberResume==0:
				break
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("win32 local groups:"+str(exc))

	cgiEnv.OutCgiRdf(grph,"LAYOUT_SPLINE")

if __name__ == '__main__':
	Main()
