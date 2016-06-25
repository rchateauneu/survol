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

def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = rdflib.Graph()

	# Ca va etre un parametre.
	subscriptionName=Azure.DefaultSubscription()

	(subscription_id,certificate_path) = lib_credentials.GetCredentials( "Azure", subscriptionName )

	sms = ServiceManagementService(subscription_id, certificate_path)

	subscriptionNode = subscription.MakeUri( subscriptionName )

	result = sms.list_locations()
	for loca in result:
		locaNode = location.MakeUri( loca.name, subscriptionName )

		grph.add( ( subscriptionNode, lib_common.MakeProp("Location"), locaNode ) )

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()

