#!/usr/bin/env python

"""
NET VIEW command
"""

# http://ss64.com/nt/net_share.html

# D:\Projects\Divers\Reverse\PythonStyle\htbin\sources>net view
# Server Name            Remark
# 
# -------------------------------------------------------------------------------
# \\LONW000063245
# \\LONW00050624
# \\LONW00051025
# \\LONW00051272
# \\LONW00051815
# \\LONW00051877
# \\LONW00052163

import sys
import re
import lib_util
import lib_uris
import lib_common
from lib_properties import pc

Usable = lib_util.UsableWindows


def Main():
    cgiEnv = lib_common.CgiEnv()

    grph = cgiEnv.GetGraph()

    net_view_cmd = ["net", "view"]

    net_view_pipe = lib_common.SubProcPOpen(net_view_cmd)

    net_view_last_output, net_view_err = net_view_pipe.communicate()

    # Converts to string for Python3.
    asstr = net_view_last_output.decode("utf-8")
    lines = asstr.split('\n')

    seen_hyphens = False

    for lin in lines:
        if re.match(".*-------.*",lin):
            seen_hyphens = True
            continue

        if re.match(".*The command completed successfully.*",lin):
            break
        if not seen_hyphens:
            continue

        tst_view = re.match(r'^\\\\([A-Za-z0-9_$]+)', lin)
        if not tst_view:
            continue

        shr_srv = tst_view.group(1)

        share_srv_node = lib_uris.gUriGen.SmbServerUri(shr_srv)
        grph.add((lib_common.nodeMachine, pc.property_smbview, share_srv_node))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
