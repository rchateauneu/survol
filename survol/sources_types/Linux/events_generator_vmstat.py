#!/usr/bin/env python

"""vmstat command"""


import os
import re
import sys
import subprocess
import lib_common
import lib_util
from lib_properties import pc
import lib_properties

Usable = lib_util.UsableLinux


def Main():
    proc_open = None

    # TODO: The values are arbitrarily added to the node of the host, but a time-stamp should be somewhere.
    current_node_hostname = lib_common.gUriGen.HostnameUri(lib_util.currentHostname)

    # procs -----------memory---------- ---swap-- -----io---- -system-- ------cpu-----
    #  r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa st
    #  0  0 217344 152232 112880 1573408    0    0     1    43    0    1  1  1 98  0  0
    def _vmstat_to_graph(grph, vmstat_header, input_line):
        split_header = re.split(' +', vmstat_header.strip())
        split_line = re.split(' +', input_line.strip())

        if len(split_header) != len(split_line):
            sys.stderr.write("Different lengths: [%s] / [%s]\n" % (vmstat_header, input_line))
            return

        for column_name, column_value in zip(split_header, split_line):
            if column_name == "":
                continue
            property_node = lib_properties.MakeProp("vmstat.%s" % column_name)
            # TODO: Add a timestamp.
            grph.add((current_node_hostname, property_node, lib_common.NodeLiteral(column_value)))

    def main_snapshot():
        iostat_cmd = ["vmstat", ]

        cgiEnv = lib_common.CgiEnv()

        Main.proc_popen = subprocess.Popen(iostat_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
        result_lines = Main.proc_popen.stdout.readlines()
        grph = cgiEnv.GetGraph()
        _vmstat_to_graph(grph, result_lines[1], result_lines[2])

        cgiEnv.OutCgiRdf()

    def main_events():
        # TODO: The delay could be a parameter.
        iostat_cmd = ["vmstat", "1", ]

        # Contains the last header read.
        iostat_header = []

        cgiEnv = lib_common.CgiEnv()

        Main.proc_popen = subprocess.Popen(iostat_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)

        line_counter = 0
        for current_line in Main.proc_popen.stdout.readlines():
            line_counter += 1
            if line_counter == 1:
                continue
            if line_counter == 2:
                vmstat_header = current_line
                continue

            if not current_line:
                continue

            grph = cgiEnv.ReinitGraph()
            _vmstat_to_graph(grph, vmstat_header, current_line)
            cgiEnv.OutCgiRdf()

    try:
        if lib_util.is_snapshot_behaviour():
            main_snapshot()
        else:
            main_events()
    except Exception as exc:
        lib_common.ErrorMessageHtml("vmstat error:%s" % str(exc))
    finally:
        if proc_open:
            proc_open.kill()
            proc_open.communicate()
            proc_open.terminate()


if __name__ == '__main__':
    Main()
