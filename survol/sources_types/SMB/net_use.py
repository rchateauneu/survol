#!/usr/bin/env python

"""
NET USE command
"""

# D:\Projects\Divers\Reverse\PythonStyle\htbin\sources>net use
# New connections will be remembered.
# 
# Status       Local     Remote                    Network
# 
# -------------------------------------------------------------------------------
# OK           E:        \\pars01110240\software   Microsoft Windows Network
# OK           F:        \\infsapps\applications   Microsoft Windows Network
# OK           H:        \\londata002.uk.net.intra\EM-IT
#                                                 Microsoft Windows Network
# OK           S:        \\LONSHR-IRG\IRG          Microsoft Windows Network
# OK           U:        \\LONDATA001.uk.net.intra\UK936025
#                                                 Microsoft Windows Network
# The command completed successfully.

import sys
import re
import socket
import lib_util
import lib_common
from lib_properties import pc
import lib_smb

Usable = lib_smb.UsableNetCommands

def Main():
    cgiEnv = lib_common.CgiEnv()

    grph = cgiEnv.GetGraph()

    net_use_cmd = ["net", "use"]

    net_use_pipe = lib_common.SubProcPOpen(net_use_cmd)

    net_use_last_output, net_use_err = net_use_pipe.communicate()

    # Converts to string for Python3.
    asstr = net_use_last_output.decode("utf-8")
    lines = asstr.split('\n')

    seen_hyphens = False

    # When the remote field is too long, the content is split into two lines.
    curr_status = ''
    curr_local = ''
    curr_remote = ''
    curr_network = ''

    for lin in lines:
        assert isinstance(lin, str)
        if re.match(".*-------.*",lin):
            seen_hyphens = True
            continue

        if re.match(".*The command completed successfully.*",lin):
            break
        if not seen_hyphens:
            continue

        if curr_local == '':
            curr_status = lin[:12]
            curr_local = lin[15:]
            if lin[48] == ' ':
                curr_remote = lin[16:47]
                curr_network = lin[49:]
            else:
                curr_remote = lin[16:]
                # Will read network at next line.
                continue
        else:
            curr_network = lin[48:]

        curr_remote = curr_remote.strip()

        # "\\192.168.0.15\rchateau   Microsoft Windows Network"
        curr_local = curr_local.strip().split(" ")[0]

        share_node = lib_common.gUriGen.SmbShareUri(curr_remote)
        grph.add((lib_common.gUriGen.FileUri(curr_local + ':'), pc.property_mount, share_node))

        # Reset the line, will read next disk.
        curr_local = ''

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
