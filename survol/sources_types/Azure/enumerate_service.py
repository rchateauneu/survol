#!/usr/bin/env python

"""
Azure services
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
from sources_types.Azure import location
from sources_types.Azure import service

Usable = lib_util.UsableWindows

def EnumServices(grph,subscriptionName):
	(subscription_id,certificate_path) = lib_credentials.GetCredentials( "Azure", subscriptionName )

	sms = ServiceManagementService(subscription_id, certificate_path)

	subscriptionNode = subscription.MakeUri( subscriptionName )

	try:
		# This throws when running with Apache. OK with cgiserver.py
		lstSrvs = sms.list_hosted_services()
	except:
		lib_common.ErrorMessageHtml("Unexpected error:" + str( sys.exc_info() ) )

	for srv in lstSrvs:
		servNode = service.MakeUri( srv.service_name, subscriptionName )
		grph.add( ( subscriptionNode, lib_common.MakeProp("Service"), servNode ) )

		# There will be duplicates.
		locaNode = location.MakeUri( srv.hosted_service_properties.location, subscriptionName )
		grph.add( ( servNode, lib_common.MakeProp("Location"), locaNode ) )

		grph.add( ( servNode, pc.property_rdf_data_nolist1, lib_common.NodeUrl(srv.url) ) )

def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	subscriptions = lib_credentials.GetCredentialsNames( "Azure" )

	for subscriptionName in subscriptions:
		EnumServices(grph,subscriptionName)

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()

