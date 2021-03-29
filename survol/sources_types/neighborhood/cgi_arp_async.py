#!/usr/bin/env python

"""
ARP address resolution protocol
"""

import sys
import re
import socket
import threading
import time
import logging

import lib_uris
import lib_arp
import lib_util
import lib_common
from lib_properties import pc


def GetMacVendor(mac_address):
    """
    This returns the vendor name of this mac address.
    There is no garantee that this website is reliable, so there is a strict time-out.
    It returns something like:
    "Hewlett Packard"|"B0:5A:DA"|"11445 Compaq Center Drive,Houston 77070,US"|"B05ADA000000"|"B05ADAFFFFFF"|"US"|"MA-L"
    """
    url_mac = "https://macvendors.co/api/%s/pipe" % mac_address
    if mac_address in ["", "FF-FF-FF-FF-FF-FF"]:
        return None

    try:
        import urllib2
        req = urllib2.Request(url_mac)
        req.add_header('User-Agent', "API Browser")
        resp = urllib2.urlopen(req)
        content = resp.readlines()[0]

        split_mac = content.split("|")
        return split_mac[0]
    except Exception as exc:
        logging.error("Caught: %s" % exc)
        # Any error returns a none strng: Thisinformation is not that important.
        return "Cannot determine vendor"

# TODO: Add an option to make it asynchronous or synchronous or without DNS.
# Otherwise we must maintain several versions.


class LookupThread(threading.Thread):
    """
        This thread class gets an IP address, does a dns lookup,
        then creates RDF lookup.
        Asynchronous lookups are much faster when there are done in parallel.
    """
    def __init__(self, linSplit, grph, grph_lock, map_hostnames_ipcount):
        self.linSplit = linSplit
        self.grph = grph
        self.grph_lock = grph_lock
        self.map_hostnames_ipcount = map_hostnames_ipcount

        threading.Thread.__init__(self)

    def run(self):
        hst_addr, host_name, aliases = lib_arp.GetArpHostAliases(self.linSplit[0])
        top_dig = hst_addr.split(".")[0]
        mac_address = self.linSplit[1].upper()
        nc_company = GetMacVendor(mac_address)
        arp_type = self.linSplit[2]
        host_itf = self.linSplit[3].split()

        # Now we create a node in rdflib, and we need a mutex for that.
        with self.grph_lock:
            try:
                lst_ip_addrs = self.map_hostnames_ipcount[host_name]

                if hst_addr in lst_ip_addrs:
                    return

                lst_ip_addrs.add(hst_addr)
                label_ext = "_%d" % len(lst_ip_addrs)
            except KeyError:
                self.map_hostnames_ipcount[host_name] = {hst_addr}
                label_ext = ""

            host_node = lib_uris.gUriGen.HostnameUri(host_name)
            if hst_addr != host_name:
                self.grph.add((host_node, lib_common.MakeProp("IP address"+label_ext), lib_util.NodeLiteral(hst_addr)))

            if top_dig == "224":
                # TODO: Check multicast detection.
                self.grph.add((host_node, pc.property_information, lib_util.NodeLiteral("Multicast")))
            else:
                if nc_company:
                    self.grph.add((host_node, lib_common.MakeProp("MAC"+label_ext), lib_util.NodeLiteral(mac_address)))
                    self.grph.add((host_node, lib_common.MakeProp("Vendor"+label_ext), lib_util.NodeLiteral(nc_company)))

            # static/dynamic
            if arp_type != "":
                self.grph.add((host_node, lib_common.MakeProp("ARP_type"), lib_util.NodeLiteral(arp_type)))

            # TODO: Create network interface class.
            if host_itf:
                self.grph.add((host_node, lib_common.MakeProp("Interface"), lib_util.NodeLiteral(host_itf)))


def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    grph = cgiEnv.GetGraph()

    # Several threads can add nodes at the same time.
    grph_lock = threading.Lock()

    map_hostnames_ipcount = dict()

    lookup_threads = []

    set_ips = set()

    for lin_split in lib_arp.GetArpEntries():
        ip_addr = lin_split[0]
        # Remove possible duplicates.
        if ip_addr in set_ips:
            continue
        set_ips.add(ip_addr)
        logging.debug("lin_split=%s", str(lin_split))
        thr = LookupThread(lin_split, grph, grph_lock, map_hostnames_ipcount)
        thr.start()
        lookup_threads.append(thr)

    for thread in lookup_threads:
        thread.join()

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
