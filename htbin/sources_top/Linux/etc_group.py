#!/usr/bin/python

import sys
import rdflib
# import lib_entities.lib_entity_user
import lib_common
from lib_properties import pc

cgiEnv = lib_common.CgiEnv("Groups on a Linux platform")

if not 'linux' in sys.platform:
	lib_common.ErrorMessageHtml("/etc/group for Linux only")

grph = rdflib.Graph()

for lin_gr in open("/etc/group"):
	split_gr = lin_gr.split(':')
	grpId = split_gr[2]
	grpNode = lib_common.gUriGen.GroupUri( split_gr[0] )
	grph.add( ( grpNode, pc.property_groupid, rdflib.Literal(grpId) ) )

cgiEnv.OutCgiRdf( grph )


