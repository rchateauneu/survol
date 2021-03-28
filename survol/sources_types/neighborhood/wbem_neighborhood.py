#!/usr/bin/env python

"""
Neighboring WBEM agents.
"""

import sys
import logging
import lib_util
import lib_wbem
import lib_common
import lib_credentials
from lib_properties import pc
from sources_types import neighborhood as survol_neighborhood


# Similar to portal_wbem.py except that:
# - This script uses SLP.
# - This script can only give top-level URLs.


def _add_from_wbem_cimom(grph, cimom_wbem):
    parsed_url = lib_util.survol_urlparse(cimom_wbem)
    host_wbem = parsed_url.hostname
    logging.debug("host_wbem=%s", host_wbem)
    if not host_wbem:
        return None

    # http://mymachine:8000/survol/namespaces_wbem.py?xid=http:%2F%2F192.168.0.17:5988/.
    cimom_wbem_cgi = cimom_wbem.replace("//", "%2f%2f")
    logging.debug("cimomWbem=%s cimom_wbem_cgi=%s", cimom_wbem, cimom_wbem_cgi)

    url_wbem = lib_wbem.WbemAllNamespacesUrl(cimom_wbem_cgi)
    wbem_node = lib_common.NodeUrl(url_wbem)

    wbem_host_node = lib_uris.gUriGen.HostnameUri(host_wbem)

    grph.add((wbem_node, pc.property_information, lib_util.NodeLiteral(cimom_wbem)))
    grph.add((wbem_node, pc.property_host, wbem_host_node))

    return wbem_node


def _wbem_servers_display(grph):
    cred_names = lib_credentials.get_credentials_names("WBEM")
    logging.debug("WbemServersDisplay")
    for cimom_wbem in cred_names:
        logging.debug("WbemServersDisplay cimomWbem=%s", cimom_wbem)

        # The credentials are not needed until a Survol agent uses HTTPS.
        wbem_node = _add_from_wbem_cimom(grph, cimom_wbem)
        if not wbem_node:
            continue
        grph.add((wbem_node, pc.property_information, lib_util.NodeLiteral("Static definition")))


def Main():
    # If this flag is set, the script uses SLP to discover WBEM Agents.
    paramkey_slp = "Service Location Protocol"

    cgiEnv = lib_common.ScriptEnvironment(
        parameters={paramkey_slp: False}
    )

    flag_slp = bool(cgiEnv.get_parameters(paramkey_slp))

    grph = cgiEnv.GetGraph()

    _wbem_servers_display(grph)

    if flag_slp:
        dict_services = survol_neighborhood.GetSLPServices("survol")
        for key_service in dict_services:
            wbem_node = _add_from_wbem_cimom(grph, key_service)

            if not wbem_node:
                continue

            grph.add((wbem_node, pc.property_information, lib_util.NodeLiteral("Service Location Protocol")))

            attrs_service = dict_services[key_service]
            for key_attr in attrs_service:
                prop_attr = lib_common.MakeProp(key_attr)
                val_attr = attrs_service[key_attr]
                grph.add((wbem_node, prop_attr, lib_util.NodeLiteral(val_attr)))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
