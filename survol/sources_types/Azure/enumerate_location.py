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


def _enumerate_locations(grph, subscription_name):
    subscription_id, certificate_path = lib_credentials.GetCredentials("Azure", subscription_name)

    sms = ServiceManagementService(subscription_id, certificate_path)

    subscription_node = subscription.MakeUri(subscription_name)

    try:
        # This throws when running with Apache. OK with cgiserver.py
        lst_locas = sms.list_locations()
    except Exception as exc:
        lib_common.ErrorMessageHtml("Unexpected error:" + str(exc))

    for loca in lst_locas:
        loca_node = location.MakeUri(loca.name, subscription_name)
        grph.add((subscription_node, lib_common.MakeProp("Location"), loca_node))


def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    grph = cgiEnv.GetGraph()

    subscriptions = lib_credentials.get_credentials_names( "Azure" )

    for subscription_name in subscriptions:
        _enumerate_locations(grph, subscription_name)

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()

