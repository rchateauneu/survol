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
import subprocess

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
        lib_common.ErrorMessageHtml("WinDump not implemented yet on Windows")
        return ["WinDump",]
    else:
        # Option -n so no conversion of addresses and port numbers.
        return ["tcpdump", "-n"]


def Main(loop_number=1):
    tcpdump_cmd = _get_tcmp_dump_command()

    cgiEnv = lib_common.CgiEnv()
    proc_open = None
    try:
        sys.stderr.write("tcpdump_cmd=%s\n" % str(tcpdump_cmd))
        proc_popen = subprocess.Popen(tcpdump_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
        sys.stderr.write("tcpdump started pid=i%d\n" % proc_open.pid)
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
        sys.stderr.write("tcpdump. Caught:%s\n" % str(exc))
        lib_common.ErrorMessageHtml("tcpdump error:%s" % str(exc))
    finally:
        sys.stderr.write("tcpdump. Ending\n")
        if proc_open:
            sys.stderr.write("tcpdump. Killing subprocess\n")
            proc_open.kill()
            stdout_data, stderr_data = proc_open.communicate()
            sys.stderr.write("tcpdump. stdout_data=%s\n" % stdout_data)
            sys.stderr.write("tcpdump. stderr_data=%s\n" % stderr_data)
            proc_open.terminate()
        else:
            sys.stderr.write("tcpdump. Subprocess not started\n")


################################################################################

if __name__ == '__main__':
    if lib_util.is_snapshot_behaviour():
        Main()
    else:
        while True:
            Main(1000000)
            time.sleep(20)
