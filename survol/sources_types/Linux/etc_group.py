#!/usr/bin/env python

"""
Groups on a Linux platform
"""

import sys

import lib_uris
import lib_util
import lib_common
from lib_properties import pc


def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    grph = cgiEnv.GetGraph()

    for lin_gr in open("/etc/group"):
        split_gr = lin_gr.split(':')
        grp_id = split_gr[2]
        grp_node = lib_uris.gUriGen.GroupUri(split_gr[0])
        grph.add((grp_node, pc.property_groupid, lib_util.NodeLiteral(grp_id)))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
