#!/usr/bin/python

import rdflib
import sys

import lib_common
from lib_properties import pc

cgiEnv = lib_common.CgiEnv("Users belonging to a Linux group")
groupName = cgiEnv.GetId()

if not 'linux' in sys.platform:
	lib_common.ErrorMessageHtml("/etc/group on Linux only")

etc_group = open("/etc/group")

grph = rdflib.Graph()

split_users = []
grpNode = lib_common.gUriGen.GroupUri( groupName )

grpId = "UnknownGroup:"+groupName
for lin_gr in etc_group:
	split_gr = lin_gr.split(':')
	try:
		if split_gr[0] == groupName:
			users_list = split_gr[3]
			grpId = split_gr[2]
			split_users = users_list.split(',')
			break
	except IndexError:
		pass

grph.add( ( grpNode, pc.property_groupid, rdflib.Literal(grpId) ) )

for user_name in split_users:
	user_node = lib_common.gUriGen.UserUri( user_name )
	grph.add( ( user_node, pc.property_group, grpNode ) )

cgiEnv.OutCgiRdf(grph)

