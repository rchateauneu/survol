#!/usr/bin/env python

"""
Windows domain machines
"""

import os
import sys
import socket
import lib_util
import lib_common
from lib_properties import pc

import win32com.client
import win32net
import pywintypes


def Main():
    cgiEnv = lib_common.CgiEnv()

    grph = cgiEnv.GetGraph()

    try:
        # TODO: Extends this to have machines as parameters.
        # domain_controller = win32net.NetGetDCName (None, None)
        # domain_controller = win32net.NetGetDCName (None, "")
        # ... throws: "Could not find domain controller for this domain."
        # domain_controller = win32net.NetGetDCName ("127.0.0.1", None)
        # domain_controller = win32net.NetGetDCName ("192.168.1.83", None)
        # domain_controller = win32net.NetGetDCName ("192.168.1.83", "")
        # ... throws: "The service has not been started."

        domain_controller = win32net.NetGetDCName("", "")
    except pywintypes.error as exc:
        lib_common.ErrorMessageHtml(str(exc))

    domain_name = win32net.NetUserModalsGet (domain_controller, 2)['domain_name']
    DEBUG("Domain name:" + domain_name)
    DEBUG("Domaine Controller:" + domain_controller)
    DEBUG("Info=" + str(win32net.NetUserModalsGet (domain_controller, 2)))

    node_domain = lib_common.gUriGen.SmbDomainUri(domain_name)
    node_controller = lib_common.gUriGen.HostnameUri(domain_controller)

    grph.add((node_domain, pc.property_controller, node_controller))

    cnt = 0

    adsi = win32com.client.Dispatch("ADsNameSpaces")
    nt = adsi.GetObject("", "WinNT:")
    result = nt.OpenDSObject("WinNT://%s" % domain_name, "", "", 0)
    result.Filter = ["computer"]

    for machine in result:
        if machine.Name[0] == '$':
            continue

        # Prefer not to print them because of possible race condition.
        node_machine = lib_common.gUriGen.HostnameUri(machine.Name)
        grph.add((node_domain, pc.property_domain, node_machine))
        cnt += 1
        # TODO: It works fine until 1000 nodes, but after that takes ages to run. What can we do ?????
        # HARDCODE_LIMIT
        if cnt > 1000:
            ERROR("COULD NOT RUN IT TILL THE END")
            break

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
