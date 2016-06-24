#!/usr/bin/python

"""
Azure services
"""

import sys
import socket
import rdflib
import psutil
import rdflib
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

def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = rdflib.Graph()

	# En fait ca va etre un parametre.
	subscriptionName=Azure.DefaultSubscription()

	(subscription_id,certificate_path) = lib_credentials.GetCredentials( "Azure", subscriptionName )

	sms = ServiceManagementService(subscription_id, certificate_path)

	subscriptionNode = subscription.MakeUri( subscriptionName )

	result = sms.list_hosted_services()
	for srv in result:
		servNode = service.MakeUri( srv.service_name )
		grph.add( ( subscriptionNode, lib_common.MakeProp("Service"), servNode ) )

		# There will be duplicates.
		locaNode = location.MakeUri( srv.hosted_service_properties.location )
		grph.add( ( servNode, lib_common.MakeProp("Location"), locaNode ) )

		grph.add( ( servNode, pc.property_rdf_data_nolist1, rdflib.term.URIRef(srv.url) ) )

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()

