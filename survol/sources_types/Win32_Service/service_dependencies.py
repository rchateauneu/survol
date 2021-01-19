#!/usr/bin/env python

"""
Windows service dependencies
"""

import os
import sys
imrpot logging
import lib_util
import lib_common
from lib_properties import pc

import time
import datetime
from sources_types import Win32_Service

Usable = lib_util.UsableWindows


def TimeStamp():
	ts = time.time()
	return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S') + ":"


def Main():
	cgiEnv = lib_common.CgiEnv(can_process_remote = True)
	serviceName = cgiEnv.GetId()
	serviceHost = cgiEnv.GetHost()
	grph = cgiEnv.GetGraph()

	logging.debug("serviceName=%s", serviceName )

	# Unfortunately we build the complete network for just one service.
	dictServiceMap = Win32_Service.BuildSrvNetwork( serviceHost )

	# BEWARE: Do not print str(dictServiceMap) because it hangs about ten minutes !!!!!!!!!!!!
	# BEWARE: Do not print str(dictServiceMap) because it hangs about ten minutes !!!!!!!!!!!!
	# BEWARE: Do not print str(dictServiceMap) because it hangs about ten minutes !!!!!!!!!!!!

	logging.debug(TimeStamp()+ "serviceName=%s dictServiceMap=%s", serviceName, "str(dictServiceMap)" )

	serviceDict = dictServiceMap[ serviceName ]

	serviceNode = Win32_Service.DictServiceToNode( grph, serviceDict, serviceHost )

	# There should not be any circular dependency, so no need to create the dependent nodes in advance.
	for subServiceNameIn in serviceDict["depends_in"]:
		subServiceDictIn = dictServiceMap[ subServiceNameIn ]
		subServiceNodeIn = Win32_Service.DictServiceToNode( grph, subServiceDictIn, serviceHost )
		grph.add( (serviceNode, pc.property_service, subServiceNodeIn ) )

	for subServiceNameOut in serviceDict["depends_out"]:
		subServiceDictOut = dictServiceMap[ subServiceNameOut ]
		subServiceNodeOut = Win32_Service.DictServiceToNode( grph, subServiceDictOut, serviceHost )
		grph.add( (subServiceNodeOut, pc.property_service, serviceNode ) )

	# TODO: Edges should be better displayed. Change colors, more informaiton in the name.
	# TODO Also, they could be bidirectional, have more informaiton in the name.
	# TODO: Add attributes to the URL, for example:
	# TODO: Type;Titre;Couleur;Taille;Fleches
	# TODO: sub-process;Pid=123;Red:1;SinpleArrow
	# TODO: socket;Telnet;Green;BidirectionnalArrow

	# cgiEnv.OutCgiRdf("LAYOUT_RECT")
	# cgiEnv.OutCgiRdf()
	cgiEnv.OutCgiRdf("LAYOUT_SPLINE")


if __name__ == '__main__':
	Main()
