#!/usr/bin/env python

"""
Azure subscription services
"""

import sys

from azure import *
from azure.servicemanagement import *

import lib_util
import lib_common
from lib_properties import pc
import lib_credentials

from sources_types import Azure
from sources_types.Azure import subscription
from sources_types.Azure import location
from sources_types.Azure import service

Usable = lib_util.UsableWindows


def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    grph = cgiEnv.GetGraph()

    subscription_name = cgiEnv.m_entity_id_dict["Subscription"]

    subscription_id, certificate_path = lib_credentials.GetCredentials("Azure", subscription_name)

    sms = ServiceManagementService(subscription_id, certificate_path)

    subscription_node = subscription.MakeUri(subscription_name)

    try:
        # This throws when running with Apache. OK with cgiserver.py
        lst_srvs = sms.list_hosted_services()
    except Exception as exc:
        lib_common.ErrorMessageHtml("Unexpected error:" + str(exc))

    for srv in lst_srvs:
        serv_node = service.MakeUri(srv.service_name, subscription_name)
        grph.add((subscription_node, lib_common.MakeProp("Service"), serv_node))

        # There will be duplicates.
        loca_node = location.MakeUri( srv.hosted_service_properties.location, subscription_name)
        grph.add((serv_node, lib_common.MakeProp("Location"), loca_node))

        grph.add((serv_node, pc.property_rdf_data_nolist1, lib_common.NodeUrl(srv.url)))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()

