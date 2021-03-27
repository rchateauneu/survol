#!/usr/bin/env python

"""
Neighboring Survol agents.

Distant Survol agents can broadcast their presence with SLP.
Set the Service Location Protocol flag to enable this detection.
"""

import sys
import logging

import lib_uris
import lib_util
import lib_common
import lib_credentials
from lib_properties import pc
from sources_types import neighborhood as survol_neighborhood


def _add_survol_node(grph, host_survol, url_survol_clean):
    logging.debug("AddSurvolNode hostSurvol=%s", host_survol)
    survol_host_node = lib_common.gUriGen.HostnameUri(host_survol)

    curr_disp_mode = lib_util.GuessDisplayMode()

    # Several possibilities:
    # - Open a new HTML page with this URL. Or SVG, passed on the current mode.
    # - If we are in D3 mode, this should return a JSON object from the other agent.
    if curr_disp_mode == "json":
        server_box = lib_uris.OtherAgentBox(host_survol)

        # This is the URL of the remote host, on the remote agent.
        node_remote_host = server_box.HostnameUri(host_survol)
        grph.add((survol_host_node, lib_common.MakeProp("Survol host"), node_remote_host))

        node_survol_url = lib_common.NodeUrl(url_survol_clean)
        grph.add((survol_host_node, lib_common.MakeProp("Survol agent"), node_survol_url))
    else:
        url_survol_moded = lib_util.AnyUriModed(url_survol_clean, curr_disp_mode)

        node_survol_url = lib_common.NodeUrl(url_survol_moded)

        # Should check the URL to be sure it is valid.
        grph.add((survol_host_node, lib_common.MakeProp("Survol agent"), node_survol_url))

    return node_survol_url


def _callback_node_adder(grph, url_survol):
    parsed_url = lib_util.survol_urlparse(url_survol)
    host_survol = parsed_url.hostname
    if host_survol:
        node_survol_url = _add_survol_node(grph, host_survol, url_survol)
        return node_survol_url
    else:
        return None


def _survol_servers_display(grph):
    cred_names = lib_credentials.get_credentials_names("Survol")
    logging.debug("SurvolServersDisplay")
    for url_survol in cred_names:
        # The credentials are not needed until a Survol agent uses HTTPS.
        _callback_node_adder(grph, url_survol)


def Main():
    # If this flag is set, the script uses SLP to discover Survol Agents.
    paramkey_slp = "Service Location Protocol"

    cgiEnv = lib_common.ScriptEnvironment(
        parameters = {paramkey_slp: False }
    )

    flag_slp = bool(cgiEnv.get_parameters(paramkey_slp))

    grph = cgiEnv.GetGraph()

    _survol_servers_display(grph)

    if flag_slp:
        dict_services = survol_neighborhood.GetSLPServices("survol")
        for key_service in dict_services:
            node_survol_url = _callback_node_adder(grph, key_service)
            grph.add((node_survol_url,
                      pc.property_information,
                      lib_util.NodeLiteral("Service Location Protocol")))
            attrs_service = dict_services[key_service]
            for key_attr in attrs_service:
                prop_attr = lib_common.MakeProp(key_attr)
                val_attr = attrs_service[key_attr]
                grph.add((node_survol_url, prop_attr, lib_util.NodeLiteral(val_attr)))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
