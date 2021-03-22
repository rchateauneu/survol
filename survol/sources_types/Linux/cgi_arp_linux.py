#!/usr/bin/env python

"""
ARP command for Linux
"""

# TODO: Maybe there is one output per interface.
import sys
import re
import logging

import lib_uris
import lib_util
import lib_common
from lib_properties import pc


def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    grph = cgiEnv.GetGraph()

    arp_cmd = ["/sbin/arp", "-a"]

    arp_pipe = lib_common.SubProcPOpen(arp_cmd)

    arp_last_output, arp_err = arp_pipe.communicate()

    # Converts to string for Python3.
    asstr = arp_last_output.decode("utf-8")

    lines = asstr.split('\n')

    for lin in lines:
        logging.debug("Lin=%s", lin)

        # Maybe should check if other interfaces ??
        # Maybe should create the entity "network interface",
        # instead of this confusion between machines and addresses.

        # BThomehub.home (192.168.1.254) at 18:62:2C:63:98:6A [ether] on eth0
        mtch_arp = re.match(r"([^ ]+) \(([^)]+)\) at ([^ ]+) .*", lin)

        if not mtch_arp:
            continue

        host_name = mtch_arp.group(1)
        host_node = lib_uris.gUriGen.HostnameUri(host_name)
        grph.add((host_node, pc.property_information, lib_util.NodeLiteral(mtch_arp.group(2))))
        grph.add((host_node, pc.property_information, lib_util.NodeLiteral(mtch_arp.group(3))))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
