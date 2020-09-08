#!/usr/bin/env python

import lib_common
import lib_util
import os
import re
from lib_properties import pc
import lib_properties

def Usable(entity_type, entity_ids_arr):
    """Runs on Linux only, in asynchronous mode"""
    return lib_util.UsableLinux(entity_type, entity_ids_arr) and lib_util.UsableAsynchronousSource(entity_type,
                                                                                                   entity_ids_arr)
################################################################################

# Device:            tps   Blk_read/s   Blk_wrtn/s   Blk_read   Blk_wrtn
# sda               3,00         0,00        48,00          0         48
# sdb               0,00         0,00         0,00          0          0



# This runs in the HTTP server and uses the data from the queue.
# This reads a record from the queue and builds a RDF relation with it.
def _io_stat_to_graph(grph, spl, iostat_header):
    device_node = lib_common.gUriGen.DiskUri(spl[0])
    property_name_to_node = dict()

    for idx in range(1, len(spl)):
        # No idea why doubles are written with a comma. Maybe the locale?
        qty = float(spl[idx].replace(",", "."))

        property_name = iostat_header[idx]
        property_node = property_name_to_node.get(property_name, lib_properties.MakeProp(property_name))
        grph.add((device_node, property_node, lib_common.NodeLiteral(qty)))


# This runs tcpdump, parses output data from it.
def Main(loop_number=1):
    # TODO: The delay could be a parameter.
    iostat_cmd = "iostat -d 1"

    # Contains the last header read.
    iostat_header = []

    cgiEnv = lib_common.CgiEnv()
    for lin in os.popen(iostat_cmd):
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


if __name__ == '__main__':
    if lib_util.is_snapshot_behaviour():
        Main()
    else:
        while True:
            Main(1000000)
