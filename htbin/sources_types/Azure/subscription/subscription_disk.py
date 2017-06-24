#!/usr/bin/python

"""
Azure subscription disks
"""

import sys
import socket
import psutil
import lib_util
import lib_common
from lib_properties import pc
import lib_credentials
from azure import *
from azure.servicemanagement import *

from sources_types import Azure
from sources_types.Azure import subscription
from sources_types.Azure import disk
from sources_types.Azure import location

Usable = lib_util.UsableWindows


# TODO: L affichage deconne quand on essaye defaire des colonnes.

# TODO: Il faudrait ramener un disque Azure a un disque normal, peut-etre ?


def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	# subscriptionName=Azure.DefaultSubscription()
	subscriptionName = cgiEnv.m_entity_id_dict["Subscription"]

	(subscription_id,certificate_path) = lib_credentials.GetCredentials( "Azure", subscriptionName )

	sms = ServiceManagementService(subscription_id, certificate_path)

	subscriptionNode = subscription.MakeUri( subscriptionName )

	# Some information printed
	grph.add( ( subscriptionNode, lib_common.MakeProp(".requestid"), lib_common.NodeLiteral(sms.requestid)) )
	grph.add( ( subscriptionNode, lib_common.MakeProp(".x_ms_version"), lib_common.NodeLiteral(sms.x_ms_version)) )

	propDisk = lib_common.MakeProp("Disk")
	propDiskLabel = lib_common.MakeProp("Label")
	propDiskLocation = lib_common.MakeProp("Location")
	propMediaLink = lib_common.MakeProp("Media Link")

	try:
		# This throws when running with Apache. OK with cgiserver.py
		lstDisks = sms.list_disks()
	except:
		lib_common.ErrorMessageHtml("Unexpected error:" + str( sys.exc_info() ) )

	for dsk in lstDisks:
		sys.stderr.write("dsk=%s\n"%str(dir(dsk)))
		nodeDisk = disk.MakeUri( dsk.name, subscriptionName )
		grph.add( ( subscriptionNode, propDisk, nodeDisk ) )
		grph.add( ( nodeDisk, lib_common.MakeProp("Size"), lib_common.NodeLiteral(dsk.logical_disk_size_in_gb )) )

		# TODO: This www url does not work. WHY ???
		urlDisk = dsk.media_link
		grph.add( ( nodeDisk, propMediaLink, lib_common.NodeUrl(urlDisk)) )

		if dsk.affinity_group:
			affGroup = dsk.affinity_group
			grph.add( ( nodeDisk, lib_common.MakeProp("Affinity group"), lib_common.NodeLiteral(affGroup)) )

		grph.add( ( nodeDisk, lib_common.MakeProp("Source image name"), lib_common.NodeLiteral(dsk.source_image_name)) )
		grph.add( ( nodeDisk, lib_common.NodeLiteral("Operating System"), lib_common.NodeLiteral(dsk.os)) )
		# grph.add( ( nodeDisk, lib_common.NodeLiteral("Hosted Service Name"), lib_common.NodeLiteral(dsk.hosted_service_name)) )

		if dsk.is_corrupted:
			grph.add( ( nodeDisk, lib_common.NodeLiteral("Corrupted"), lib_common.NodeLiteral(dsk.is_corrupted)) )

		grph.add( ( nodeDisk, lib_common.NodeLiteral("Label"), lib_common.NodeLiteral(dsk.label)) )
		# grph.add( ( nodeDisk, lib_common.MakeProp("Affinity group"), lib_common.NodeLiteral("dsk.affinity_group")) )
		sys.stderr.write("dsk.attached_to=%s\n"%str(dir(dsk.attached_to)))

		nodeLocation = location.MakeUri( dsk.location, subscriptionName )
		grph.add( ( nodeDisk, propDiskLocation, nodeLocation ) )

	# cgiEnv.OutCgiRdf("LAYOUT_RECT",[propDisk,propDiskLocation,propMediaLink])
	# cgiEnv.OutCgiRdf("LAYOUT_RECT",[propDisk,propDiskLocation])
	# cgiEnv.OutCgiRdf("LAYOUT_RECT",[propDisk])
	cgiEnv.OutCgiRdf("LAYOUT_RECT_TB")

if __name__ == '__main__':
	Main()
