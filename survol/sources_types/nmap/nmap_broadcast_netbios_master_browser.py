#!/usr/bin/env python

"""
Nmap master browsers discovery

Discovers master browsers and their managed domains.
"""

import re
import sys
import socket
import logging
import xml.dom.minidom
import lib_uris
import lib_util
import lib_common
from lib_properties import pc

# https://nmap.org/nsedoc/scripts/broadcast-netbios-master-browser.html
#
# Starting Nmap 7.12 ( https://nmap.org ) at 2017-11-30 07:54 GMT
# Pre-scan script results:
# | broadcast-netbios-master-browser:
# | ip            server           domain
# |_192.168.0.15  WDMYCLOUDMIRROR  WORKGROUP
# logging.warning: No targets were specified, so 0 hosts scanned.
# Nmap done: 0 IP addresses (0 hosts up) scanned in 4.32 seconds
#


def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    args = ["nmap", '-oX', '-', '--script', "broadcast-netbios-master-browser", ]

    # The returned IP address is wrong when launched from a Windows machine where the DB is running.
    p = lib_common.SubProcPOpen(args)

    grph = cgiEnv.GetGraph()

    nmap_last_output, nmap_err = p.communicate()

    dom = xml.dom.minidom.parseString(nmap_last_output)

    # <script id="broadcast-netbios-master-browser" output="..."/>

    # TODO: Remove line "ip server domain"

    for a_script in dom.getElementsByTagName('script'):
        # output="&#xa;ip server domain&#xa;192.168.0.15  WDMYCLOUDMIRROR  WORKGROUP&#xa;"
        an_output = a_script.getAttributeNode('output').value.strip()
        logging.debug("an_output=%s", str(an_output))
        arr_split = [a_wrd.strip() for a_wrd in an_output.split("\n")]

        logging.debug("arr_split=%s", str(arr_split))

        the_mach_full = arr_split[1].strip()
        logging.debug("the_mach_full=%s", str(the_mach_full))
        mach_split = re.split( "[\t ]+", the_mach_full)
        logging.debug("mach_split=%s", str(mach_split))
        mach_ip = mach_split[0].strip()
        mach_nam = mach_split[1].strip()
        name_domain = mach_split[2].strip()

        node_host = lib_uris.gUriGen.HostnameUri(mach_nam)
        grph.add((node_host, lib_common.MakeProp("IP address"), lib_util.NodeLiteral(mach_ip)))
        grph.add((node_host, lib_common.MakeProp("Domain"), lib_util.NodeLiteral(name_domain)))
        grph.add((node_host, pc.property_information, lib_util.NodeLiteral(arr_split[0])))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
