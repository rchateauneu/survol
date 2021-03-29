#!/usr/bin/env python

"""
Windows domain machines
"""

# http://timgolden.me.uk/python/win32_how_do_i/list_machines_in_a_domain.html

import os
import sys
import socket
import logging

import lib_uris
import lib_util
import lib_common
from lib_properties import pc

def Main():
    cgiEnv = lib_common.ScriptEnvironment()
    machine_name = cgiEnv.GetId()
    if lib_util.is_local_address(machine_name):
        machine_name = None

    if not lib_util.isPlatformWindows:
        lib_common.ErrorMessageHtml("win32 Python library only on Windows platforms")

    try:
        import win32com.client
        import win32net
        import pywintypes
    except ImportError:
        lib_common.ErrorMessageHtml("win32 Python library not installed")

    grph = cgiEnv.GetGraph()

    try:
        # Parameters:
        # Name of remote server on which the function is to execute. If None, local computer.
        # Domain name. If None, name of the domain controller for the primary domain.
        # If machine_name="LONW00052257.EURO.NET.INTRA", then it must be truncated to "LONW00052257"
        # Maybe this is a Netbios machine name ?? No idea, just make it work, for the moment.
        if machine_name == None:
            mach_split = None
        else:
            mach_split = machine_name.split('.')[0]
        logging.warning("machine_name:%s mach_split:%s", machine_name, mach_split)
        domain_controller = win32net.NetGetDCName(mach_split, None)
    except pywintypes.error as exc:
        lib_common.ErrorMessageHtml("NetGetDCName:mach_split=%s %s" % (mach_split, str(exc)))

    # This returns the domain name, for example "EURO".
    domain_name = win32net.NetUserModalsGet(domain_controller, 2)['domain_name']
    logging.debug("Domain name:%s", domain_name)
    logging.debug("Domaine Controller:%s", domain_controller)
    logging.debug("Info=%s", str(win32net.NetUserModalsGet(domain_controller, 2)))

    node_domain = lib_uris.gUriGen.SmbDomainUri(domain_name)
    node_controller = lib_uris.gUriGen.HostnameUri(domain_controller)

    grph.add((node_domain, pc.property_controller, node_controller))

    cnt = 0

    # Sounds like these are the machines in the domain...
    adsi = win32com.client.Dispatch("ADsNameSpaces")
    nt = adsi.GetObject("", "WinNT:")
    result = nt.OpenDSObject("WinNT://%s" % domain_name, "", "", 0)
    result.Filter = ["computer"]

    for machine in result:
        if machine.Name[0] == '$':
            continue

        logging.debug("machine_name=%s", machine.Name)
        node_machine = lib_uris.gUriGen.HostnameUri(machine.Name)
        grph.add((node_domain, pc.property_domain, node_machine))
        cnt += 1
        # TODO: It works fine until 1000 nodes, but after that takes ages to run. What can we do ?????
        # HARDCODE_LIMIT
        if cnt > 1000:
            logging.warning("COULD NOT RUN IT TILL THE END")
            break

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
