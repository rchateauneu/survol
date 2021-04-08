#!/usr/bin/env python

"""
Azure subscription informations
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

Usable = lib_util.UsableWindows


def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    grph = cgiEnv.GetGraph()

    subscription_name = cgiEnv.m_entity_id_dict["Subscription"]

    subscription_id, certificate_path = lib_credentials.GetCredentials("Azure", subscription_name)

    sms = ServiceManagementService(subscription_id, certificate_path)

    subscription_node = subscription.MakeUri(subscription_name)

    # There are a lot of informations
    grph.add((subscription_node, lib_common.MakeProp(".cert_file"), lib_util.NodeLiteral(sms.cert_file)))
    grph.add((subscription_node, lib_common.MakeProp(".requestid"), lib_util.NodeLiteral(sms.requestid)))
    grph.add((subscription_node, lib_common.MakeProp(".x_ms_version"), lib_util.NodeLiteral(sms.x_ms_version)))
    grph.add((subscription_node, lib_common.MakeProp("Azure"), lib_util.NodeLiteral(str(dir(sms)))))

    #propOperatingSystem = lib_common.MakeProp("Operating System")
    #for opsys in sms.list_operating_systems():
    #    grph.add((subscription_node, propOperatingSystem, lib_util.NodeLiteral(opsys.family_label)))

    prop_operating_system_family = lib_common.MakeProp("Operating System Family")

    try:
        # This throws when running with Apache. OK with cgiserver.py
        lst_oses = sms.list_operating_system_families()
    except Exception as exc:
        lib_common.ErrorMessageHtml("Unexpected error:" + str(exc))

    for opsys in lst_oses:
        grph.add((subscription_node, prop_operating_system_family, lib_util.NodeLiteral(opsys.label)))

    cgiEnv.OutCgiRdf("LAYOUT_RECT", [prop_operating_system_family])


if __name__ == '__main__':
    Main()
