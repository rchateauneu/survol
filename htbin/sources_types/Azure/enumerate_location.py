#!/usr/bin/python

"""
Azure locations
"""

import sys
import socket
import rdflib
import psutil
import lib_util
import lib_common
from lib_properties import pc
import lib_credentials
from azure import *
from azure.servicemanagement import *

from sources_types import Azure
from sources_types.Azure import subscription
from sources_types.Azure import location

Usable = lib_util.UsableWindows

def EnumLoca(grph,subscriptionName):
	(subscription_id,certificate_path) = lib_credentials.GetCredentials( "Azure", subscriptionName )

	sms = ServiceManagementService(subscription_id, certificate_path)

	subscriptionNode = subscription.MakeUri( subscriptionName )

	try:
		# This throws when running with Apache. OK with cgiserver.py
		lstLocas = sms.list_locations()
	except:
		lib_common.ErrorMessageHtml("Unexpected error:" + str( sys.exc_info() ) )

	for loca in lstLocas:
		locaNode = location.MakeUri( loca.name, subscriptionName )

		grph.add( ( subscriptionNode, lib_common.MakeProp("Location"), locaNode ) )

def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	subscriptions = lib_credentials.GetCredentialsNames( "Azure" )

	for subscriptionName in subscriptions:
		EnumLoca(grph,subscriptionName)

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()

