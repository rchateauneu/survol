#!/usr/bin/env python

"""
Azure locations
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

Usable = lib_util.UsableWindows


def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    grph = cgiEnv.GetGraph()

    subscription_name = cgiEnv.m_entity_id_dict["Subscription"]

    subscription_id, certificate_path = lib_credentials.GetCredentials("Azure", subscription_name)

    sms = ServiceManagementService(subscription_id, certificate_path)

    subscriptionNode = subscription.MakeUri(subscription_name)

    try:
        # This throws when running with Apache. OK with cgiserver.py
        lst_locations = sms.list_locations()
    except Exception as exc:
        lib_common.ErrorMessageHtml("Unexpected error:" + str(exc))

    result = lst_locations
    for loca in result:
        locaNode = location.MakeUri(loca.name, subscription_name)
        grph.add((subscriptionNode, lib_common.MakeProp("Location"), locaNode))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
