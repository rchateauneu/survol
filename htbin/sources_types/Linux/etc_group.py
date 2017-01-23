#!/usr/bin/python

"""
Groups on a Linux platform
"""

import sys
import rdflib
import lib_util
import lib_common
from lib_properties import pc

Usable = lib_util.UsableLinux

def Main():
	cgiEnv = lib_common.CgiEnv()

	if not lib_util.isPlatformLinux:
		lib_common.ErrorMessageHtml("/etc/group for Linux only")

	grph = rdflib.Graph()

	for lin_gr in open("/etc/group"):
		split_gr = lin_gr.split(':')
		grpId = split_gr[2]
		grpNode = lib_common.gUriGen.GroupUri( split_gr[0] )
		grph.add( ( grpNode, pc.property_groupid, rdflib.Literal(grpId) ) )

	cgiEnv.OutCgiRdf( grph )


if __name__ == '__main__':
	Main()
