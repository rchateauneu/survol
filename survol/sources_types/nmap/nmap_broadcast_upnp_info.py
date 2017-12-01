#!/usr/bin/python

"""
Nmap broadcast UPNP information

Extract system information from the UPnP service by sending a multicast query,
"""


import re
import sys
import socket
import xml.dom.minidom
import lib_util
import lib_common
from lib_properties import pc

# https://nmap.org/nsedoc/scripts/broadcast-upnp-info.html
#
# Starting Nmap 7.12 ( https://nmap.org ) at 2017-11-30 08:30 GMT
# Pre-scan script results:
# | broadcast-upnp-info:
# |   192.168.0.14
# |       Server: WINDOWS, UPnP/1.0, Intel MicroStack/1.0.1497
# |       Location: http://192.168.0.14:62240/
# |         Webserver: WINDOWS, UPnP/1.0, Intel MicroStack/1.0.1497
# |         Name: rchateau-HP
# |         Manufacturer: CyberLink Corporation
# |         Model Descr: CyberLink UPnP Media Server
# |         Model Name: CyberLink Media Server
# |         Model Version: 12.0
# |   192.168.0.17
# |       Server: Linux/4.4.14-200.fc22.x86_64 UPnP/1.0 GUPnP/0.20.17
# |       Location: http://192.168.0.17:41347/0585ea5f-4fe4-4baa-a308-a15da83de3cb.xml
# |         Name: Remi Chateauneu's media on Unknown-30-b5-c2-02-0c-b5-2.home
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
# |         Name: rchateau-HP
# |         Manufacturer: CyberLink Corporation
# |         Model Descr: CyberLink UPnP Media Server
# |         Model Name: CyberLink Media Server
# |_        Model Version: 12.0
# WARNING: No targets were specified, so 0 hosts scanned.
# Nmap done: 0 IP addresses (0 hosts up) scanned in 10.80 seconds
#
