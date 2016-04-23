#!/usr/bin/python

# List of open files for one process only.

import re
import sys
import subprocess
import rdflib

import lib_common
import lib_util
from lib_properties import pc

# Parses "500(guest)"
def ParseIdNam(str):
	sys.stderr.write("ParseIdNam:"+str+"\n")
	mtch = re.match( "^([0-9]*)\(([^)]*)\)$", str )
	if mtch:
		return ( mtch.group(1), mtch.group(2) )
	return ( -1, "" )

# Properly splits this string.
# Maybe we could use the keys but they depend on the locale.
# uid=500(rchateau) gid=500(guest) groupes=500(guest),81(audio)
def SplitId(str):
	sys.stderr.write("SplitId:"+str+"\n")
	arr = str.split(' ')
	resu = []
	for substr in arr:
		resu.append( substr.split('=')[1] )
	return resu

def Main():
	cgiEnv = lib_common.CgiEnv("Groups of a Linux user")
	userNameWithHost = cgiEnv.GetId()

	if not 'linux' in sys.platform:
		lib_common.ErrorMessageHtml("id command on Linux only")

	# Usernames have the syntax user@host
	userSplit = userNameWithHost.split('@')
	userName = userSplit[0]

	if len( userSplit ) > 1:
		userHost = userSplit[1]
		if userHost != lib_util.currentHostname:
			# TODO: Should interrogate other host with "finger" protocol.
			lib_common.ErrorMessageHtml("Cannot get user properties on different host:" + userHost)

	grph = rdflib.Graph()

	userNode = lib_common.gUriGen.UserUri( userName )

	id_cmd = [ "id", userName ]

	id_pipe = subprocess.Popen(id_cmd, bufsize=100000, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

	( id_last_output, id_err ) = id_pipe.communicate()

	lines = id_last_output.split('\n')
	sys.stderr.write("id=" + userName + " lines="+str(lines)+"\n")

	sys.stderr.write("Lines=" + str(len(lines) ) + "\n" )

	# $ id rchateau
	# uid=500(rchateau) gid=500(guest) groupes=500(guest),81(audio)

	firstLine = lines[0]

	sys.stderr.write("First="+firstLine+"\n")

	firstSplit = SplitId( firstLine )

	userId = ParseIdNam( firstSplit[0] )[0]

	grph.add( ( userNode, pc.property_userid, rdflib.Literal(userId) ) )

	for grpStr in firstSplit[2].split(','):
		(grpId,grpNam) = ParseIdNam(grpStr)
		grpNode = lib_common.gUriGen.GroupUri(grpNam)
		grph.add( ( grpNode, pc.property_groupid, rdflib.Literal(grpId) ) )
		grph.add( ( userNode, pc.property_group, grpNode ) )

	cgiEnv.OutCgiRdf(grph)



if __name__ == '__main__':
	Main()
