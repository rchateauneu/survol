#!/usr/bin/env python

"""vmstat command"""


import os
import sys
import subprocess
import logging
import rdflib

import lib_common
import lib_util
import lib_kbase
from lib_properties import pc
import lib_properties


def Main():
    proc_open = None

    # procs -----------memory---------- ---swap-- -----io---- -system-- ------cpu-----
    #  r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa st
    #  0  0 217344 152232 112880 1573408    0    0     1    43    0    1  1  1 98  0  0
    def _vmstat_to_graph(cgiEnv, vmstat_header, input_line):
        grph = cgiEnv.ReinitGraph()
        split_header = vmstat_header.split()
        split_line = input_line.split()

        if len(split_header) != len(split_line):
            sys.stderr.write("Different lengths: [%s] / [%s]\n" % (split_header, split_line))
            return
        #sys.stderr.write("_vmstat_to_graph: [%s]\n" % split_line)

        current_node_hostname = lib_common.gUriGen.HostnameUri(lib_util.currentHostname)
        property_vmstat = lib_properties.MakeProp("vmstat")

        sample_root_node = rdflib.BNode()
        grph.add((current_node_hostname, property_vmstat, sample_root_node))

        timestamp_node = lib_kbase.time_stamp_now_node()
        grph.add((sample_root_node, pc.property_information, timestamp_node))

        for column_name, column_value in zip(split_header, split_line):
            #sys.stderr.write("column_name: [%s]\n" % column_name.decode())
            if column_name == "":
                continue
            # Column name is binary and converted to unicode.
            property_node = lib_properties.MakeProp("vmstat.%s" % column_name.decode())
            # TODO: Add a timestamp.
            grph.add((sample_root_node, property_node, lib_util.NodeLiteral(column_value)))
        cgiEnv.OutCgiRdf("LAYOUT_RECT", [property_vmstat])

    def main_snapshot():
        vmstat_cmd = ["vmstat", ]

        cgiEnv = lib_common.CgiEnv()

        logging.debug(__file__ + " Snapshot Starting process:%s" % str(vmstat_cmd))
        Main.proc_popen = subprocess.Popen(vmstat_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
        result_lines = Main.proc_popen.stdout.readlines()
        _vmstat_to_graph(cgiEnv, result_lines[1], result_lines[2])

        #cgiEnv.OutCgiRdf()

    def main_events():
        # TODO: The delay could be a parameter.
        vmstat_cmd = ["vmstat", "1",]

        cgiEnv = lib_common.CgiEnv()

        logging.debug(__file__ + " Events Starting process:%s" % str(vmstat_cmd))
        Main.proc_popen = subprocess.Popen(vmstat_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
        logging.debug(__file__ + " Events Started")

        line_counter = 0
        while True:
            current_line = Main.proc_popen.stdout.readline()
            logging.debug(__file__ + " Events Read:%s" % current_line)
            line_counter += 1
            if line_counter == 1:
                continue
            if line_counter == 2:
                # Contains the last header read.
                vmstat_header = current_line
                continue

            if not current_line:
                continue

            _vmstat_to_graph(cgiEnv, vmstat_header, current_line)

    try:
        if lib_util.is_snapshot_behaviour():
            main_snapshot()
        else:
            logging.debug(__file__ + " events")
            main_events()
    except Exception as exc:
        lib_common.ErrorMessageHtml("vmstat error:%s" % str(exc))
    finally:
        if proc_open:
            proc_open.kill()
            proc_open.communicate()
            proc_open.terminate()


if __name__ == '__main__':
    logging.debug("Start "+__file__)
    Main()
