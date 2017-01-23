#!/usr/bin/python

"""
Azure subscription disks
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
from sources_types.Azure import disk
from sources_types.Azure import location

Usable = lib_util.UsableWindows


# TODO: L affichage deconne quand on essaye defaire des colonnes.

# TODO: Il faudrait ramener un disque Azure a un disque normal, peut-etre ?


def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = rdflib.Graph()

	# subscriptionName=Azure.DefaultSubscription()
	subscriptionName = cgiEnv.m_entity_id_dict["Subscription"]

	(subscription_id,certificate_path) = lib_credentials.GetCredentials( "Azure", subscriptionName )

	sms = ServiceManagementService(subscription_id, certificate_path)

	subscriptionNode = subscription.MakeUri( subscriptionName )

	# Some information printed
	grph.add( ( subscriptionNode, lib_common.MakeProp(".requestid"), rdflib.Literal(sms.requestid)) )
	grph.add( ( subscriptionNode, lib_common.MakeProp(".x_ms_version"), rdflib.Literal(sms.x_ms_version)) )

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
		grph.add( ( nodeDisk, lib_common.MakeProp("Size"), rdflib.Literal(dsk.logical_disk_size_in_gb )) )

		# TODO: This www url does not work. WHY ???
		urlDisk = dsk.media_link
		grph.add( ( nodeDisk, propMediaLink, rdflib.URIRef(urlDisk)) )

		if dsk.affinity_group:
			affGroup = dsk.affinity_group
			grph.add( ( nodeDisk, lib_common.MakeProp("Affinity group"), rdflib.Literal(affGroup)) )

		grph.add( ( nodeDisk, lib_common.MakeProp("Source image name"), rdflib.Literal(dsk.source_image_name)) )
		grph.add( ( nodeDisk, rdflib.Literal("Operating System"), rdflib.Literal(dsk.os)) )
		# grph.add( ( nodeDisk, rdflib.Literal("Hosted Service Name"), rdflib.Literal(dsk.hosted_service_name)) )

		if dsk.is_corrupted:
			grph.add( ( nodeDisk, rdflib.Literal("Corrupted"), rdflib.Literal(dsk.is_corrupted)) )

		grph.add( ( nodeDisk, rdflib.Literal("Label"), rdflib.Literal(dsk.label)) )
		# grph.add( ( nodeDisk, lib_common.MakeProp("Affinity group"), rdflib.Literal("dsk.affinity_group")) )
		sys.stderr.write("dsk.attached_to=%s\n"%str(dir(dsk.attached_to)))

		nodeLocation = location.MakeUri( dsk.location, subscriptionName )
		grph.add( ( nodeDisk, propDiskLocation, nodeLocation ) )

	# cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT",[propDisk,propDiskLocation,propMediaLink])
	# cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT",[propDisk,propDiskLocation])
	# cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT",[propDisk])
	cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT_TB")

if __name__ == '__main__':
	Main()
