#!/usr/bin/env python

"""
Nmap broadcast UPNP information

Extract system information from the UPnP service by sending a multicast query,
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

# https://nmap.org/nsedoc/scripts/broadcast-upnp-info.html
# nmap -sV --script=broadcast-upnp-info
#  -sV: Probe open ports to determine service/version info
#
# Starting Nmap 7.12 ( https://nmap.org ) at 2017-11-30 08:30 GMT
# Pre-scan script results:
# | broadcast-upnp-info:
# |   192.168.0.14
# |       Server: WINDOWS, UPnP/1.0, Intel MicroStack/1.0.1497
# |       Location: http://192.168.0.14:62240/
# |         Webserver: WINDOWS, UPnP/1.0, Intel MicroStack/1.0.1497
# |         Name: mymachine
# |         Manufacturer: CyberLink Corporation
# |         Model Descr: CyberLink UPnP Media Server
# |         Model Name: CyberLink Media Server
# |         Model Version: 12.0
# |   192.168.0.17
# |       Server: Linux/4.4.14-200.fc22.x86_64 UPnP/1.0 GUPnP/0.20.17
# |       Location: http://192.168.0.17:41347/0585ea5f-4fe4-4baa-a308-a15da83de3cb.xml
# |         Name: John Smith's media on Unknown-30-b5-c2-02-0c-b5-2.home
# |         Manufacturer: Rygel Developers.
# |         Model Name: Rygel
# |         Model Version: 0.26.1
# |   192.168.0.13
# |       Server: Microsoft-Windows/6.3 UPnP/1.0 UPnP-Device-Host/1.0
# |       Location: http://192.168.0.13:2869/upnphost/udhisapi.dll?content=uuid:21a44432-6249-4b80-bd85-65baea006cfa
# |         Webserver: Microsoft-Windows/6.3 UPnP/1.0 UPnP-Device-Host/1.0 Microsoft-HTTPAPI/2.0
# |   192.168.0.15
# |       Server: Linux/3.2.40, UPnP/1.0, Portable SDK for UPnP devices/1.6.6
# |       Location: http://192.168.0.15:49152/nasdevicedesc.xml
# |         Webserver: Linux/3.2.40, UPnP/1.0, Portable SDK for UPnP devices/1.6.6
# |         Name: WDMyCloudMirror
# |         Manufacturer: Western Digital Corporation
# |         Model Descr: 2-Bay Personal Cloud Storage
# |         Model Name: WDMyCloudMirror
# |         Model Version: BZVM
# |   192.168.0.1
# |       Server: Linux/2.6.18_pro500 UPnP/1.0 MiniUPnPd/1.5
# |       Location: http://192.168.0.1:5000/rootDesc.xml
# |         Webserver: Linux/2.6.18_pro500 UPnP/1.0 MiniUPnPd/1.5
# |         Name: ARRIS TG2492LG-85 Router
# |         Manufacturer: ARRIS
# |         Model Descr: ARRIS TG2492LG-85 Router
# |         Model Name: ARRIS TG2492LG-85 Router
# |         Model Version: 4.5.0.18_0603
# |         Name: WANDevice
# |         Manufacturer: ARRIS
# |         Model Descr: WANDevice
# |         Model Name: WANDevice
# |         Model Version: 20160603
# |         Name: WANConnectionDevice
# |         Manufacturer: ARRIS
# |         Model Descr: Residential Gateway
# |         Model Name: TG2492LG-85
# |         Model Version: 20160603
# |   192.168.0.20
# |       Server: WINDOWS, UPnP/1.0, Intel MicroStack/1.0.1497
# |       Location: http://192.168.0.20:62240/
# |         Webserver: WINDOWS, UPnP/1.0, Intel MicroStack/1.0.1497
# |         Name: mymachine
# |         Manufacturer: CyberLink Corporation
# |         Model Descr: CyberLink UPnP Media Server
# |         Model Name: CyberLink Media Server
# |_        Model Version: 12.0
# logging.warning: No targets were specified, so 0 hosts scanned.
# Nmap done: 0 IP addresses (0 hosts up) scanned in 10.80 seconds
#


def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    args = ["nmap", '-oX', '-', '-sV', '--script', "broadcast-upnp-info", ]

    # The returned IP address is wrong when launched from a Windows machine where the DB is running.
    p = lib_common.SubProcPOpen(args)

    grph = cgiEnv.GetGraph()

    nmap_last_output, nmap_err = p.communicate()

    dom = xml.dom.minidom.parseString(nmap_last_output)

    # <script id="broadcast-upnp-info" output="&#xa;  192.168.0.20&#xa;      Server: WINDOWS, UPnP/1.0, Intel MicroStack/1.0.14
    # 97&#xa;      Location: http://192.168.0.20:62240/&#xa;        Webserver: WINDOWS, UPnP/1.0, Intel MicroStack/1.0.1497&#xa;        Na
    # me: mymachine&#xa;        Manufacturer: CyberLink Corporation&#xa;        Model Descr: CyberLink UPnP Media Server&#xa;        Mod
    # el Name: CyberLink Media Server&#xa;        Model Version: 12.0&#xa;  192.168.0.13&#xa;      Server: Microsoft-Windows/6.3 UPnP/1.0
    # UPnP-Device-Host/1.0&#xa;      Location: http://192.168.0.13:2869/upnphost/udhisapi.dll?content=uuid:21a44432-6249-4b80-bd85-65baea0
    # 06cfa&#xa;        Webserver: Microsoft-Windows/6.3 UPnP/1.0 UPnP-Device-Host/1.0 Microsoft-HTTPAPI/2.0&#xa;  192.168.0.15&#xa;
    # Server: Linux/3.2.40, UPnP/1.0, Portable SDK for UPnP devices/1.6.6&#xa;      Location: http://192.168.0.15:49152/nasdevicedesc.xml&
    # #xa;        Webserver: Linux/3.2.40, UPnP/1.0, Portable SDK for UPnP devices/1.6.6&#xa;        Name: WDMyCloudMirror&#xa;        Man
    # ufacturer: Western Digital Corporation&#xa;        Model Descr: 2-Bay Personal Cloud Storage&#xa;        Model Name: WDMyCloudMirror
    # &#xa;        Model Version: BZVM&#xa;  192.168.0.1&#xa;      Server: Linux/2.6.18_pro500 UPnP/1.0 MiniUPnPd/1.5&#xa;      Location:
    # http://192.168.0.1:5000/rootDesc.xml&#xa;        Webserver: Linux/2.6.18_pro500 UPnP/1.0 MiniUPnPd/1.5&#xa;        Name: ARRIS TG249
    # 2LG-85 Router&#xa;        Manufacturer: ARRIS&#xa;        Model Descr: ARRIS TG2492LG-85 Router&#xa;        Model Name: ARRIS TG2492
    # LG-85 Router&#xa;        Model Version: 4.5.0.18_0603&#xa;        Name: WANDevice&#xa;        Manufacturer: ARRIS&#xa;        Model
    # Descr: WANDevice&#xa;        Model Name: WANDevice&#xa;        Model Version: 20160603&#xa;        Name: WANConnectionDevice&#xa;
    #      Manufacturer: ARRIS&#xa;        Model Descr: Residential Gateway&#xa;        Model Name: TG2492LG-85&#xa;        Model Version:
    #  20160603&#xa;  192.168.0.14&#xa;      Server: Microsoft-Windows-NT/5.1 UPnP/1.0 UPnP-Device-Host/1.0&#xa;      Location: http://192
    # .168.0.14:2869/upnphost/udhisapi.dll?content=uuid:b44cacc7-118e-4159-bf2a-7783481dd3b4&#xa;        Webserver: Microsoft-Windows-NT/5
    # .1 UPnP/1.0 UPnP-Device-Host/1.0 Microsoft-HTTPAPI/2.0&#xa;"/>

    # Just in case there would be several "script" elements but we expect only one.
    for a_script in dom.getElementsByTagName('script'):
        an_output = a_script.getAttributeNode('output').value.strip()
        logging.debug("an_output=%s", str(an_output))
        arr_split = [a_wrd.strip() for a_wrd in an_output.split("\n")]

        logging.debug("arr_split=%s",str(arr_split))

        for one_wrd in arr_split:
            logging.debug("one_wrd=%s", one_wrd)
            one_split = [a_split.strip() for a_split in one_wrd.split(":")]

            if len(one_split) > 1:
                # In case there would be more than one ":" but we expect a key-value pair.
                a_key = one_split[0]
                a_val = ":".join(one_split[1:])
                logging.debug("one_split=%s" % one_split)
                if a_key == "Location":
                    # The value is something like "http://192.168.0.14:62240/"
                    grph.add((node_host, lib_common.MakeProp(a_key), lib_common.NodeUrl(a_val)))
                else:
                    grph.add((node_host, lib_common.MakeProp(a_key), lib_util.NodeLiteral(a_val)))
            else:
                # TODO: Should translate the IP address into the machine name.
                mach_ip = one_split[0]
                logging.debug("mach_ip=%s",mach_ip)
                try:
                    mach_name = socket.gethostbyaddr(mach_ip)[0]
                    node_host = lib_uris.gUriGen.HostnameUri(mach_name)
                    if mach_name != mach_ip:
                        grph.add((node_host, pc.property_ip_addr, lib_util.NodeLiteral(mach_ip)))
                except Exception as exc:
                    # If unknown host or any other problem.
                    logging.error("Caught:%s" % exc)
                    node_host = lib_uris.gUriGen.HostnameUri(mach_ip)
                    grph.add((node_host, pc.property_information, lib_util.NodeLiteral(str(exc))))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
