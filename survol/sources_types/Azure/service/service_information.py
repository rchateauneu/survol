#!/usr/bin/env python

"""
Information about an Azure service
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
from sources_types.Azure import location
from sources_types.Azure import service

Usable = lib_util.UsableWindows


def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    service_name = cgiEnv.m_entity_id_dict["Id"]

    subscription_name = cgiEnv.m_entity_id_dict["Subscription"]

    grph = cgiEnv.GetGraph()

    subscription_id, certificate_path = lib_credentials.GetCredentials("Azure", subscription_name)

    sms = ServiceManagementService(subscription_id, certificate_path)

    subscription_node = subscription.MakeUri(subscription_name)

    srv = sms.get_hosted_service_properties(service_name)

    logging.debug("srv=%s", str(dir(srv)))
    logging.debug("deployments=%s", str(srv.deployments))
    logging.debug("srv.hosted_service_properties=%s", str(dir(srv.hosted_service_properties)))
    logging.debug("srv.hosted_service_properties.extended_properties=%s",
                  str(dir(srv.hosted_service_properties.extended_properties)))

    serv_node = service.MakeUri(srv.service_name, subscription_name)
    grph.add((subscription_node, lib_common.MakeProp("Service"), serv_node))

    loca_node = location.MakeUri(srv.hosted_service_properties.location, subscription_name)
    grph.add((serv_node, lib_common.MakeProp("Location"), loca_node))

    grph.add((serv_node, pc.property_rdf_data_nolist1, lib_common.NodeUrl(srv.url)))

    grph.add((serv_node, lib_common.MakeProp("deployments"), lib_util.NodeLiteral(str(srv.deployments))))

    # With a dot ".", they come first.
    grph.add((serv_node, lib_common.MakeProp(".affinity_group"),
              lib_util.NodeLiteral(srv.hosted_service_properties.affinity_group)))
    grph.add((serv_node, lib_common.MakeProp(".date_created"),
              lib_util.NodeLiteral(srv.hosted_service_properties.date_created)))
    grph.add((serv_node, lib_common.MakeProp(".date_last_modified"),
              lib_util.NodeLiteral(srv.hosted_service_properties.date_last_modified )))
    grph.add((serv_node, lib_common.MakeProp(".description"),
              lib_util.NodeLiteral(srv.hosted_service_properties.description)))
    grph.add((serv_node, lib_common.MakeProp(".label"),
              lib_util.NodeLiteral(srv.hosted_service_properties.label)))
    grph.add((serv_node, lib_common.MakeProp(".status"),
              lib_util.NodeLiteral(srv.hosted_service_properties.status)))

    for ext_prop in srv.hosted_service_properties.extended_properties:
        ext_val = srv.hosted_service_properties.extended_properties[ ext_prop ]
        grph.add((serv_node, lib_common.MakeProp(ext_prop), lib_util.NodeLiteral(ext_val)))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()

