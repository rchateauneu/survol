#!/usr/bin/python

"""
Information about an Azure disk
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

	# grph.add( ( diskNode, lib_common.MakeProp("xxx"), lib_common.NodeLiteral(str(dir(dsk))) ) )

	grph.add( ( diskNode, lib_common.MakeProp("affinity_group"), lib_common.NodeLiteral(dsk.affinity_group)))
	# grph.add( ( diskNode, lib_common.MakeProp("attached_to"), lib_common.NodeLiteral(str(dir(dsk.attached_to)))) )
	grph.add( ( diskNode, lib_common.MakeProp("has_operating_system"), lib_common.NodeLiteral(dsk.has_operating_system)))
	grph.add( ( diskNode, lib_common.MakeProp("is_corrupted"), lib_common.NodeLiteral(dsk.is_corrupted)) )
	grph.add( ( diskNode, lib_common.MakeProp("label"), lib_common.NodeLiteral(dsk.label)) )
	grph.add( ( diskNode, lib_common.MakeProp("Size"), lib_common.NodeLiteral(dsk.logical_disk_size_in_gb)))
	grph.add( ( diskNode, lib_common.MakeProp("name"), lib_common.NodeLiteral(dsk.name)))
	grph.add( ( diskNode, lib_common.MakeProp("os"), lib_common.NodeLiteral(dsk.os)))
	grph.add( ( diskNode, lib_common.MakeProp("source_image_name"), lib_common.NodeLiteral(dsk.source_image_name)))
	grph.add( ( diskNode, lib_common.MakeProp("media link"), lib_common.NodeUrl(dsk.media_link)))

	locaNode = location.MakeUri( dsk.location, subscriptionName )
	grph.add( ( diskNode, lib_common.MakeProp("Location"), locaNode ) )

	srvNode = service.MakeUri( dsk.attached_to.hosted_service_name, subscriptionName )
	grph.add( ( srvNode, lib_common.MakeProp("Role"), lib_common.NodeLiteral(dsk.attached_to.role_name) ) )
	grph.add( ( srvNode, lib_common.MakeProp("Deployment"), lib_common.NodeLiteral(dsk.attached_to.deployment_name) ) )
	grph.add( ( diskNode, lib_common.MakeProp("Service"), srvNode ) )

	# media_link

	cgiEnv.OutCgiRdf("LAYOUT_RECT_TB")

if __name__ == '__main__':
	Main()

