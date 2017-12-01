#!/usr/bin/python

"""
Nmap master browsers discovery

Discovers master browsers and their managed domains.
"""

import re
import sys
import socket
import xml.dom.minidom
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
# WARNING: No targets were specified, so 0 hosts scanned.
# Nmap done: 0 IP addresses (0 hosts up) scanned in 4.32 seconds
#
