#!/usr/bin/env python

"""
Azure subscription informations
"""

import sys
import socket
import lib_util
import lib_common
from lib_properties import pc
import lib_credentials
from azure import *
from azure.servicemanagement import *

from sources_types import Azure
from sources_types.Azure import subscription

Usable = lib_util.UsableWindows



def Main():
	cgiEnv = lib_common.ScriptEnvironment()

	grph = cgiEnv.GetGraph()

	# subscriptionName=Azure.DefaultSubscription()
	subscriptionName = cgiEnv.m_entity_id_dict["Subscription"]

	(subscription_id,certificate_path) = lib_credentials.GetCredentials( "Azure", subscriptionName )

	sms = ServiceManagementService(subscription_id, certificate_path)

	subscriptionNode = subscription.MakeUri( subscriptionName )

	# There are a lot of informations
	grph.add( ( subscriptionNode, lib_common.MakeProp(".cert_file"), lib_util.NodeLiteral(sms.cert_file)) )
	grph.add( ( subscriptionNode, lib_common.MakeProp(".requestid"), lib_util.NodeLiteral(sms.requestid)) )
	grph.add( ( subscriptionNode, lib_common.MakeProp(".x_ms_version"), lib_util.NodeLiteral(sms.x_ms_version)) )
	grph.add( ( subscriptionNode, lib_common.MakeProp("Azure"), lib_util.NodeLiteral(str(dir(sms))) ) )

	#propOperatingSystem = lib_common.MakeProp("Operating System")
	#for opsys in sms.list_operating_systems():
	#	sys.stderr.write("opsys=%s\n"%str(dir(opsys)))
	#	grph.add( ( subscriptionNode, propOperatingSystem, lib_util.NodeLiteral(opsys.family_label)) )

	propOperatingSystemFamily = lib_common.MakeProp("Operating System Family")

	try:
		# This throws when running with Apache. OK with cgiserver.py
		lstOSes = sms.list_operating_system_families()
	except:
		lib_common.ErrorMessageHtml("Unexpected error:" + str( sys.exc_info() ) )

	for opsys in lstOSes:
		# sys.stderr.write("opsys=%s\n"%str(dir(opsys)))
		grph.add( ( subscriptionNode, propOperatingSystemFamily, lib_util.NodeLiteral(opsys.label)) )

	cgiEnv.OutCgiRdf("LAYOUT_RECT",[propOperatingSystemFamily])

if __name__ == '__main__':
	Main()
