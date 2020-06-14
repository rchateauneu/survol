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


# Parses b"500(guest) and returns (500, "guest"")
def parse_id_name(one_string):
	mtch = re.match(br"^([0-9]*)\(([^)]*)\)$", one_string)
	if mtch:
		return mtch.group(1), mtch.group(2)
	return -1, b""

# Properly splits this string.
# Maybe we could use the keys but they depend on the locale.
# uid=500(rchateau) gid=500(guest) groupes=500(guest),81(audio)
def split_id(one_string):
	arr = one_string.split(b' ')
	resu = []
	for substr in arr:
		resu.append(substr.split(b'=')[1])
	return resu

def Main():
	cgiEnv = lib_common.CgiEnv()
	userNameWithHost = cgiEnv.GetId()

	if not lib_util.isPlatformLinux:
		lib_common.ErrorMessageHtml("id command on Linux only")

	# Usernames have the syntax user@host
	user_split = userNameWithHost.split('@')
	user_name = user_split[0]

	if len(user_split) > 1:
		user_host = user_split[1]
		if user_host != lib_util.currentHostname:
			# TODO: Should interrogate other host with "finger" protocol.
			lib_common.ErrorMessageHtml("Cannot get user properties on different host:" + user_host)

	if not user_name:
		lib_common.ErrorMessageHtml("Linux username should not be an empty string")

	grph = cgiEnv.GetGraph()

	user_node = lib_common.gUriGen.UserUri(user_name)

	id_cmd = ["id", user_name]

	id_pipe = lib_common.SubProcPOpen(id_cmd)

	(id_last_output, id_err) = id_pipe.communicate()

	lines = id_last_output.split(b'\n')
	DEBUG("id=" + user_name + " lines="+str(lines))

	# $ id rchateau
	# uid=500(rchateau) gid=500(guest) groupes=500(guest),81(audio)

	first_line = lines[0]

	first_split = split_id(first_line)

	user_id = parse_id_name(first_split[0])[0]

	grph.add((user_node, pc.property_userid, lib_common.NodeLiteral(user_id)))

	for grp_str in first_split[2].split(b','):
		(group_id, group_name) = parse_id_name(grp_str)
		grpNode = lib_common.gUriGen.GroupUri(group_name)
		grph.add( ( grpNode, pc.property_groupid, lib_common.NodeLiteral(group_id)))
		grph.add( ( user_node, pc.property_group, grpNode))

	cgiEnv.OutCgiRdf()



if __name__ == '__main__':
	Main()
