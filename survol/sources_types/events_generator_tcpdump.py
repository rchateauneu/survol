#!/usr/bin/env python

"""
tcpdump and windump
"""

# It works also for WindDump.exe, on Windows.

import os
import re
import sys
import time
import lib_util
import lib_common
from lib_properties import pc

# This parses the output of "tcpdump" or "WinDump.exe" if on Windows.
def _parse_tcpdump_line(grph, line):
    spl = line.split(' ')

    # 22:39:56.713245 IP BThomehub.home.domain > Unknown-00-18-e7-08-02-81.home.47676: 52407* 1/0/0 (87)
    if spl[1] == 'IP':

        addrRegex = r'(.*)\.([^.]*)'

        # Maybe we should have a commutative relation?
        lMatchAddr = re.match( addrRegex, spl[2], re.M|re.I)
        if not lMatchAddr:
            return
        lsocketNode = lib_common.gUriGen.AddrUri( lMatchAddr.group(1), int(lMatchAddr.group(2)) )

        rMatchAddr = re.match( addrRegex, spl[4][:-1], re.M|re.I)
        if not rMatchAddr:
            return
        rsocketNode = lib_common.gUriGen.AddrUri( rMatchAddr.group(1), int(rMatchAddr.group(2)) )

        grph.add( ( lsocketNode, pc.property_socket_end, rsocketNode ) )


def _get_tcmp_dump_command():
    if lib_util.isPlatformWindows:
        # TODO: Should test if it works.
        return "WinDump"
    else:
        # TODO: sudo is probably not appropriate.
        # Option -n so no conversion of addresses and port numbers.
        return "sudo tcpdump -n"


def Main(loop_number=1):
    tcpdump_cmd = _get_tcmp_dump_command()

    cgiEnv = lib_common.CgiEnv()
    for lin in os.popen(tcpdump_cmd):
        if not lin:
            continue
        grph = cgiEnv.ReinitGraph()
        _parse_tcpdump_line(grph, lin)
        cgiEnv.OutCgiRdf()

        loop_number -= 1
        if loop_number == 0:
            break

################################################################################

if __name__ == '__main__':
    if lib_util.is_snapshot_behaviour():
        Main()
    else:
        while True:
            Main(1000000)
            time.sleep(20)
