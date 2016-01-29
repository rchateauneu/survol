#!/usr/bin/python

"""Dependencies between Windows services"""

import os
import sys
import rdflib
import lib_common
from lib_common import pc

import time
import datetime
def TimeStamp():
	ts = time.time()
	return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S') + ":"



cgiEnv = lib_common.CgiEnv("Windows service", platform_regex = "win", can_process_remote = True)
serviceName = cgiEnv.GetId()
serviceHost = cgiEnv.GetHost()

# TODO: Apparently it hangs.

if not 'win' in sys.platform:
	lib_common.ErrorMessageHtml("win32 Python library only on Windows platforms")

import lib_entities.lib_entity_Win32_Service

grph = rdflib.Graph()

sys.stderr.write("serviceName=%s\n" % ( serviceName ) )

# Unfortunately we build the complete network for just one service.
dictServiceMap = lib_entities.lib_entity_Win32_Service.BuildSrvNetwork( serviceHost )

# BEWARE: Do not print str(dictServiceMap) because it hangs about ten minutes !!!!!!!!!!!!
# BEWARE: Do not print str(dictServiceMap) because it hangs about ten minutes !!!!!!!!!!!!
# BEWARE: Do not print str(dictServiceMap) because it hangs about ten minutes !!!!!!!!!!!!

sys.stderr.write(TimeStamp()+ "serviceName=%s dictServiceMap=%s\n" % ( serviceName, "str(dictServiceMap)" ) )

serviceDict = dictServiceMap[ serviceName ]

serviceNode = lib_entities.lib_entity_Win32_Service.DictServiceToNode( grph, serviceDict, serviceHost )

# There should not be any circular dependency, so no need to create the dependent nodes in advance.
for subServiceNameIn in serviceDict["depends_in"]:
	subServiceDictIn = dictServiceMap[ subServiceNameIn ]
	subServiceNodeIn = lib_entities.lib_entity_Win32_Service.DictServiceToNode( grph, subServiceDictIn, serviceHost )
	grph.add( (serviceNode, pc.property_service, subServiceNodeIn ) )

for subServiceNameOut in serviceDict["depends_out"]:
	subServiceDictOut = dictServiceMap[ subServiceNameOut ]
	subServiceNodeOut = lib_entities.lib_entity_Win32_Service.DictServiceToNode( grph, subServiceDictOut, serviceHost )
	grph.add( (subServiceNodeOut, pc.property_service, serviceNode ) )

# cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT")
cgiEnv.OutCgiRdf(grph)
  