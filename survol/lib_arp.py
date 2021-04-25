"""Survol code for ARP features"""

__author__      = "Remi Chateauneu"
__copyright__   = "Copyright 2020-2021, Primhill Computers"
__license__ = "GPL"

import sys
import re
import socket
import logging
import lib_util
import lib_common

# arp -a
#D:\build\IRGCMP\Other\Scripts\MRXFeed>arp -a
#
#Interface: 10.102.235.173 --- 0xb
#  Internet Address      Physical Address      Type
#  10.102.235.245        9c-93-4e-32-c6-df     dynamic
#  10.102.235.255        ff-ff-ff-ff-ff-ff     static
#  239.192.101.76        01-00-5e-40-65-4c     static
#  255.255.255.255       ff-ff-ff-ff-ff-ff     static
#
# TODO: Maybe there is one output per interface.
def _get_arp_entries_windows():
    arp_cmd = ["arp", "-a"]

    arp_pipe = lib_common.SubProcPOpen(arp_cmd)

    arp_last_output, arp_err = arp_pipe.communicate()

    # Converts to string for Python3.
    asstr = arp_last_output.decode("utf-8")
    lines = asstr.split('\n')

    for lin in lines:
        # Maybe should check if other interfaces ??
        # Maybe should create the entity "network interface",
        # instead of this confusion between machines and addresses.

        # ['255.255.255.255', 'ff-ff-ff-ff-ff-ff', 'static', '\\r']
        lin_split = re.findall(r"[^ ]+", lin)

        # Probably not the best test.
        if len(lin_split) != 4:
            continue

        if lin_split[0] == "Interface:":
            continue

        # Network interface.
        lin_split.append("")

        yield lin_split


# /sbin/arp -an
# ? (192.168.1.10) at f0:82:61:38:20:5d [ether] on wlp8s4
# ? (192.168.1.88) at <incomplete> on wlp8s4
# ? (192.168.1.17) at 54:be:f7:91:34:0d [ether] on wlp8s4
# ? (192.168.1.83) at <incomplete> on wlp8s4
# ? (192.168.1.11) at f0:cb:a1:61:c7:23 [ether] on wlp8s4
def _get_arp_entries_linux():
    arp_cmd = ["/sbin/arp", "-an"]

    arp_pipe = lib_common.SubProcPOpen(arp_cmd)

    arp_last_output, arp_err = arp_pipe.communicate()

    # TODO/ Should be a generator !
    # Converts to string for Python3.
    asstr = arp_last_output.decode("utf-8")
    lines = asstr.split('\n')

    for lin in lines:
        tmp_split = re.findall(r"[^ ]+", lin)

        if len(tmp_split) < 4:
            continue

        if tmp_split[4] == "on":
            lin_split = [tmp_split[1][1:-1], tmp_split[3], "", tmp_split[5]]
        elif tmp_split[5] == "on":
            lin_split = [tmp_split[1][1:-1], tmp_split[3], "", tmp_split[6]]
        else:
            continue

        if lin_split[1] == "<incomplete>":
            lin_split[1] = ""

        logging.debug("Split=%s", str(lin_split))

        yield lin_split


def GetArpEntries():
    if lib_util.isPlatformWindows:
        return _get_arp_entries_windows()
    if lib_util.isPlatformLinux:
        return _get_arp_entries_linux()

    lib_common.ErrorMessageHtml("Undefined platform:"+sys.platform)


def GetArpHostAliases(hst_addr):
    """This must be thread-safe"""
    try:
        host_name, aliases, _ = socket.gethostbyaddr(hst_addr)
    except socket.herror:
        host_name = hst_addr
        aliases = []

    return hst_addr, host_name, aliases

