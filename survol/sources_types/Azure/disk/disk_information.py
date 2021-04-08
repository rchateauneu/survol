#!/usr/bin/env python

"""
Information about an Azure disk
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
from sources_types.Azure import service
from sources_types.Azure import location
from sources_types.Azure import disk

Usable = lib_util.UsableWindows


def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    disk_name = cgiEnv.m_entity_id_dict["Disk"]

    subscription_name = cgiEnv.m_entity_id_dict["Subscription"]
    # subscription_name=Azure.DefaultSubscription()

    grph = cgiEnv.GetGraph()

    subscription_id, certificate_path = lib_credentials.GetCredentials("Azure", subscription_name)

    sms = ServiceManagementService(subscription_id, certificate_path)

    subscription_node = subscription.MakeUri(subscription_name)

    dsk = sms.get_disk(disk_name)

    logging.debug("dsk=%s", str(dir(dsk)))

    disk_node = disk.MakeUri(disk_name, subscription_name)
    grph.add((subscription_node, lib_common.MakeProp("Service"), disk_node))

    grph.add((disk_node, lib_common.MakeProp("affinity_group"), lib_util.NodeLiteral(dsk.affinity_group)))
    # grph.add((disk_node, lib_common.MakeProp("attached_to"), lib_util.NodeLiteral(str(dir(dsk.attached_to)))))
    grph.add((disk_node, lib_common.MakeProp("has_operating_system"), lib_util.NodeLiteral(dsk.has_operating_system)))
    grph.add((disk_node, lib_common.MakeProp("is_corrupted"), lib_util.NodeLiteral(dsk.is_corrupted)))
    grph.add((disk_node, lib_common.MakeProp("label"), lib_util.NodeLiteral(dsk.label)))
    grph.add((disk_node, lib_common.MakeProp("Size"), lib_util.NodeLiteral(dsk.logical_disk_size_in_gb)))
    grph.add((disk_node, lib_common.MakeProp("name"), lib_util.NodeLiteral(dsk.name)))
    grph.add((disk_node, lib_common.MakeProp("os"), lib_util.NodeLiteral(dsk.os)))
    grph.add((disk_node, lib_common.MakeProp("source_image_name"), lib_util.NodeLiteral(dsk.source_image_name)))
    grph.add((disk_node, lib_common.MakeProp("media link"), lib_common.NodeUrl(dsk.media_link)))

    loca_node = location.MakeUri( dsk.location, subscription_name)
    grph.add((disk_node, lib_common.MakeProp("Location"), loca_node))

    srv_node = service.MakeUri( dsk.attached_to.hosted_service_name, subscription_name)
    grph.add((srv_node, lib_common.MakeProp("Role"), lib_util.NodeLiteral(dsk.attached_to.role_name)))
    grph.add((srv_node, lib_common.MakeProp("Deployment"), lib_util.NodeLiteral(dsk.attached_to.deployment_name)))
    grph.add((disk_node, lib_common.MakeProp("Service"), srv_node))

    # media_link

    cgiEnv.OutCgiRdf("LAYOUT_RECT_TB")


if __name__ == '__main__':
    Main()

