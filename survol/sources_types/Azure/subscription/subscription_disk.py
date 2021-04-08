#!/usr/bin/env python

"""
Azure subscription disks
"""

import sys
import logging

from azure import *
from azure.servicemanagement import *

import lib_util
import lib_common
from lib_properties import pc
import lib_credentials
from sources_types import Azure
from sources_types.Azure import subscription
from sources_types.Azure import disk
from sources_types.Azure import location

Usable = lib_util.UsableWindows


def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    grph = cgiEnv.GetGraph()

    subscription_name = cgiEnv.m_entity_id_dict["Subscription"]

    subscription_id, certificate_path = lib_credentials.GetCredentials( "Azure", subscription_name)

    sms = ServiceManagementService(subscription_id, certificate_path)

    subscription_node = subscription.MakeUri(subscription_name)

    # Some information printed
    grph.add((subscription_node, lib_common.MakeProp(".requestid"), lib_util.NodeLiteral(sms.requestid)))
    grph.add((subscription_node, lib_common.MakeProp(".x_ms_version"), lib_util.NodeLiteral(sms.x_ms_version)))

    prop_disk = lib_common.MakeProp("Disk")
    prop_disk_label = lib_common.MakeProp("Label")
    prop_disk_location = lib_common.MakeProp("Location")
    prop_media_link = lib_common.MakeProp("Media Link")

    try:
        lst_disks = sms.list_disks()
    except Exception as exc:
        lib_common.ErrorMessageHtml("Unexpected error:" + str(exc))

    for dsk in lst_disks:
        logging.debug("dsk=%s", str(dir(dsk)))
        node_disk = disk.MakeUri(dsk.name, subscription_name)
        grph.add((subscription_node, prop_disk, node_disk))
        grph.add((node_disk, lib_common.MakeProp("Size"), lib_util.NodeLiteral(dsk.logical_disk_size_in_gb)))

        url_disk = dsk.media_link
        grph.add((node_disk, prop_media_link, lib_common.NodeUrl(url_disk)))

        if dsk.affinity_group:
            aff_group = dsk.affinity_group
            grph.add((node_disk, lib_common.MakeProp("Affinity group"), lib_util.NodeLiteral(aff_group)))

        grph.add((node_disk, lib_common.MakeProp("Source image name"), lib_util.NodeLiteral(dsk.source_image_name)))
        grph.add((node_disk, lib_util.NodeLiteral("Operating System"), lib_util.NodeLiteral(dsk.os)))
        # grph.add((node_disk, lib_util.NodeLiteral("Hosted Service Name"),
        #          lib_util.NodeLiteral(dsk.hosted_service_name)))

        if dsk.is_corrupted:
            grph.add((node_disk, lib_util.NodeLiteral("Corrupted"), lib_util.NodeLiteral(dsk.is_corrupted)))

        grph.add((node_disk, lib_util.NodeLiteral("Label"), lib_util.NodeLiteral(dsk.label)))
        # grph.add((node_disk, lib_common.MakeProp("Affinity group"), lib_util.NodeLiteral("dsk.affinity_group")))
        logging.debug("dsk.attached_to=%s",str(dir(dsk.attached_to)))

        node_location = location.MakeUri(dsk.location, subscription_name)
        grph.add((node_disk, prop_disk_location, node_location))

    # cgiEnv.OutCgiRdf("LAYOUT_RECT",[prop_disk,prop_disk_location,prop_media_link])
    # cgiEnv.OutCgiRdf("LAYOUT_RECT",[prop_disk,prop_disk_location])
    # cgiEnv.OutCgiRdf("LAYOUT_RECT",[prop_disk])
    cgiEnv.OutCgiRdf("LAYOUT_RECT_TB")


if __name__ == '__main__':
    Main()
