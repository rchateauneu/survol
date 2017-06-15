#!/usr/bin/python

"""
Linux group users
"""

import rdflib
import sys
import lib_util
import lib_common
from lib_properties import pc

Usable = lib_util.UsableLinux

def Main():
    cgiEnv = lib_common.CgiEnv()
    groupName = cgiEnv.GetId()

    if not lib_util.isPlatformLinux:
        lib_common.ErrorMessageHtml("/etc/group on Linux only")

    etc_group = open("/etc/group")

    grph = cgiEnv.GetGraph()

    split_users = []
    grpNode = lib_common.gUriGen.GroupUri( groupName )

    grpId = "UnknownGroup:"+groupName

    # tcpdump:x:72:
    # rchateau:x:1000:rchateau
    for lin_gr in etc_group:
        split_gr = lin_gr.split(':')
        try:
            if split_gr[0] == groupName:
                users_list = split_gr[3].strip()
                grpId = split_gr[2]
                split_users = users_list.split(',')
                break
        except IndexError:
            pass

    grph.add( ( grpNode, pc.property_groupid, rdflib.Literal(grpId) ) )

    for user_name in split_users:
        if user_name:
            user_node = lib_common.gUriGen.UserUri( user_name )
            grph.add( ( user_node, pc.property_group, grpNode ) )

    cgiEnv.OutCgiRdf()

if __name__ == '__main__':
    Main()
