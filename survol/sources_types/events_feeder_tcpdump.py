#!/usr/bin/env python

"""
tcpdump and windump
"""

# It works also for WindDump.exe, on Windows.

import os
import re
import sys
import time

import lib_uris
import lib_util
import lib_common
from lib_properties import pc
import subprocess


# This parses the output of "tcpdump" or "WinDump.exe" if on Windows.
def _parse_tcpdump_line(grph, line):
    spl = line.split(' ')

    # 22:39:56.713245 IP BThomehub.home.domain > Unknown-00-18-e7-08-02-81.home.47676: 52407* 1/0/0 (87)
    if spl[1] == 'IP':

        addr_regex = r'(.*)\.([^.]*)'

        # Maybe we should have a commutative relation?
        l_match_addr = re.match(addr_regex, spl[2], re.M|re.I)
        if not l_match_addr:
            return
        lsocket_node = lib_uris.gUriGen.AddrUri(l_match_addr.group(1), int(l_match_addr.group(2)))

        r_match_addr = re.match(addr_regex, spl[4][:-1], re.M|re.I)
        if not r_match_addr:
            return
        rsocket_node = lib_uris.gUriGen.AddrUri(r_match_addr.group(1), int(r_match_addr.group(2)))

        grph.add((lsocket_node, pc.property_socket_end, rsocket_node))


def _get_tcmp_dump_command():
    if lib_util.isPlatformWindows:
        # TODO: Should test if it works.
        lib_common.ErrorMessageHtml("WinDump not implemented yet on Windows")
        return ["WinDump",]
    else:
        # Option -n so no conversion of addresses and port numbers.
        return ["tcpdump", "-n"]


def Snapshot(loop_number=1):
    tcpdump_cmd = _get_tcmp_dump_command()

    cgiEnv = lib_common.ScriptEnvironment()
    proc_open = None
    try:
        logging.debug("tcpdump_cmd=%s" % str(tcpdump_cmd))
        proc_popen = subprocess.Popen(tcpdump_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
        logging.debug("tcpdump started pid=i%d" % proc_open.pid)
        for lin in proc_popen.stdout.readlines():
            if not lin:
                continue
            grph = cgiEnv.ReinitGraph()
            _parse_tcpdump_line(grph, lin)
            cgiEnv.OutCgiRdf()

            loop_number -= 1
            if loop_number == 0:
                break
    except Exception as exc:
        logging.debug("tcpdump. Caught:%s" % str(exc))
        lib_common.ErrorMessageHtml("tcpdump error:%s" % str(exc))
    finally:
        logging.debug("tcpdump. Ending")
        if proc_open:
            logging.debug("tcpdump. Killing subprocess")
            proc_open.kill()
            stdout_data, stderr_data = proc_open.communicate()
            logging.debug("tcpdump. stdout_data=%s" % stdout_data)
            logging.debug("tcpdump. stderr_data=%s" % stderr_data)
            proc_open.terminate()
        else:
            logging.debug("tcpdump. Subprocess not started")


def Main():
    if lib_util.is_snapshot_behaviour():
        Snapshot()
    else:
        while True:
            Snapshot(1000000)
            time.sleep(20)


if __name__ == '__main__':
    Main()
