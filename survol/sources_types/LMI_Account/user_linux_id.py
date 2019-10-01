#!/usr/bin/env python

"""
Groups of a Linux user
"""

import re
import sys
import lib_common
import lib_util
from lib_properties import pc

Usable = lib_util.UsableLinux

# Parses "500(guest)"
def ParseIdNam(str):
	DEBUG("ParseIdNam:"+str)
	mtch = re.match( r"^([0-9]*)\(([^)]*)\)$", str )
	if mtch:
		return ( mtch.group(1), mtch.group(2) )
	return ( -1, "" )

# Properly splits this string.
# Maybe we could use the keys but they depend on the locale.
# uid=500(rchateau) gid=500(guest) groupes=500(guest),81(audio)
def SplitId(str):
	DEBUG("SplitId:"+str)
	arr = str.split(' ')
	resu = []
	for substr in arr:
		resu.append( substr.split('=')[1] )
	return resu

def Main():
	cgiEnv = lib_common.CgiEnv()
	userNameWithHost = cgiEnv.GetId()

	if not lib_util.isPlatformLinux:
		lib_common.ErrorMessageHtml("id command on Linux only")

	# Usernames have the syntax user@host
	userSplit = userNameWithHost.split('@')
	userName = userSplit[0]

	if len( userSplit ) > 1:
		userHost = userSplit[1]
		if userHost != lib_util.currentHostname:
			# TODO: Should interrogate other host with "finger" protocol.
			lib_common.ErrorMessageHtml("Cannot get user properties on different host:" + userHost)

	if not userName:
		lib_common.ErrorMessageHtml("Linux username should not be an empty string")

	grph = cgiEnv.GetGraph()

	userNode = lib_common.gUriGen.UserUri( userName )

	id_cmd = [ "id", userName ]

	id_pipe = lib_common.SubProcPOpen(id_cmd)

	( id_last_output, id_err ) = id_pipe.communicate()

	lines = id_last_output.split('\n')
	DEBUG("id=" + userName + " lines="+str(lines))

	# $ id rchateau
	# uid=500(rchateau) gid=500(guest) groupes=500(guest),81(audio)

	firstLine = lines[0]

	firstSplit = SplitId( firstLine )

	userId = ParseIdNam( firstSplit[0] )[0]

	grph.add( ( userNode, pc.property_userid, lib_common.NodeLiteral(userId) ) )

	for grpStr in firstSplit[2].split(','):
		(grpId,grpNam) = ParseIdNam(grpStr)
		grpNode = lib_common.gUriGen.GroupUri(grpNam)
		grph.add( ( grpNode, pc.property_groupid, lib_common.NodeLiteral(grpId) ) )
		grph.add( ( userNode, pc.property_group, grpNode ) )

	cgiEnv.OutCgiRdf()



if __name__ == '__main__':
	Main()
