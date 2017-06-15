#!/usr/bin/python

"""
Information about an Azure disk
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
from sources_types.Azure import service
from sources_types.Azure import location
from sources_types.Azure import disk

Usable = lib_util.UsableWindows

def Main():
	cgiEnv = lib_common.CgiEnv()

	# TODO: The subscription will become a parameter with a default value.
	# serviceName = cgiEnv.GetId()
	diskName = cgiEnv.m_entity_id_dict["Disk"]

	# TODO: This should be a parameter.
	subscriptionName = cgiEnv.m_entity_id_dict["Subscription"]
	# subscriptionName=Azure.DefaultSubscription()

	grph = cgiEnv.GetGraph()

	(subscription_id,certificate_path) = lib_credentials.GetCredentials( "Azure", subscriptionName )

	sms = ServiceManagementService(subscription_id, certificate_path)

	subscriptionNode = subscription.MakeUri( subscriptionName )

	dsk = sms.get_disk(diskName)

	sys.stderr.write("dsk=%s\n"% str(dir(dsk)))

	diskNode = disk.MakeUri( diskName, subscriptionName )
	grph.add( ( subscriptionNode, lib_common.MakeProp("Service"), diskNode ) )

	# grph.add( ( diskNode, lib_common.MakeProp("xxx"), rdflib.Literal(str(dir(dsk))) ) )

	grph.add( ( diskNode, lib_common.MakeProp("affinity_group"), rdflib.Literal(dsk.affinity_group)))
	# grph.add( ( diskNode, lib_common.MakeProp("attached_to"), rdflib.Literal(str(dir(dsk.attached_to)))) )
	grph.add( ( diskNode, lib_common.MakeProp("has_operating_system"), rdflib.Literal(dsk.has_operating_system)))
	grph.add( ( diskNode, lib_common.MakeProp("is_corrupted"), rdflib.Literal(dsk.is_corrupted)) )
	grph.add( ( diskNode, lib_common.MakeProp("label"), rdflib.Literal(dsk.label)) )
	grph.add( ( diskNode, lib_common.MakeProp("Size"), rdflib.Literal(dsk.logical_disk_size_in_gb)))
	grph.add( ( diskNode, lib_common.MakeProp("name"), rdflib.Literal(dsk.name)))
	grph.add( ( diskNode, lib_common.MakeProp("os"), rdflib.Literal(dsk.os)))
	grph.add( ( diskNode, lib_common.MakeProp("source_image_name"), rdflib.Literal(dsk.source_image_name)))
	grph.add( ( diskNode, lib_common.MakeProp("media link"), rdflib.URIRef(dsk.media_link)))

	locaNode = location.MakeUri( dsk.location, subscriptionName )
	grph.add( ( diskNode, lib_common.MakeProp("Location"), locaNode ) )

	srvNode = service.MakeUri( dsk.attached_to.hosted_service_name, subscriptionName )
	grph.add( ( srvNode, lib_common.MakeProp("Role"), rdflib.Literal(dsk.attached_to.role_name) ) )
	grph.add( ( srvNode, lib_common.MakeProp("Deployment"), rdflib.Literal(dsk.attached_to.deployment_name) ) )
	grph.add( ( diskNode, lib_common.MakeProp("Service"), srvNode ) )

	# media_link

	cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT_TB")

if __name__ == '__main__':
	Main()

