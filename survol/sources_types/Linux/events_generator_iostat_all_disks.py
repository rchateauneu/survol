#!/usr/bin/env python

"""This continuously display disks state with iostat command."""

import os
import re
import subprocess
import lib_common
import lib_util
import lib_properties

Usable = lib_util.UsableLinux

################################################################################
# Typical output of the iostat command:

# Device:            tps   Blk_read/s   Blk_wrtn/s   Blk_read   Blk_wrtn
# sda               3,00         0,00        48,00          0         48
# sdb               0,00         0,00         0,00          0          0


def _io_stat_to_graph(grph, spl, iostat_header):
    """This runs in the HTTP server and uses the data from the queue.
    This reads a record from the queue and builds a RDF relation with it."""
    device_node = lib_common.gUriGen.DiskUri(spl[0])
    property_name_to_node = dict()

    for idx in range(1, len(spl)):
        # No idea why doubles are written with a comma. Maybe the locale?
        qty = float(spl[idx].replace(",", "."))

        property_name = iostat_header[idx]
        property_node = property_name_to_node.get(property_name, lib_properties.MakeProp(property_name))
        grph.add((device_node, property_node, lib_common.NodeLiteral(qty)))


def Main(loop_number=1):
    """This runs iostat and parses its output."""
    # TODO: The delay could be a parameter.
    iostat_cmd = ["iostat",  "-d", "1"]

    # Contains the last header read.
    iostat_header = []

    cgiEnv = lib_common.CgiEnv()

    proc_open = None
    try:
        proc_popen = subprocess.Popen(iostat_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
        for lin in proc_popen.stdout.readlines():
            if not lin:
                continue

            # We transfer also the header.
            spl = re.split(' +', lin)

            if spl[0] == 'Device:':
                iostat_header = spl
                return

            grph = cgiEnv.ReinitGraph()

            _io_stat_to_graph(grph, spl, iostat_header)

            cgiEnv.OutCgiRdf()

            loop_number -= 1
            if loop_number == 0:
                break
    except Exception as exc:
        lib_common.ErrorMessageHtml("iostat error:%s" % str(exc))
    finally:
        if proc_open:
            proc_open.kill()
            proc_open.communicate()
            proc_open.terminate()


if __name__ == '__main__':
    if lib_util.is_snapshot_behaviour():
        Main()
    else:
        while True:
            Main(1000000)
