#!/usr/bin/env python

"""
NET SHARE command
"""

# Share name   Resource                        Remark
#
# -------------------------------------------------------------------------------
# C$           C:\                             Default share
# D$           D:\                             Default share
# IPC$                                         Remote IPC
# ADMIN$       C:\Windows                      Remote Admin
# The command completed successfully.
#
# C:\Documents and Settings\John>net share
#
#           1         2         3         4
# 01234567890123456789012345678901234567890123456789
# Share name   Resource                        Remark
#
# -------------------------------------------------------------------------------
# IPC$                                         Remote IPC
# Remi         C:\Documents and Settings\Remi
# SharedDocs   C:\DOCUMENTS AND SETTINGS\ALL USERS\DOCUMENTS
#
# The command completed successfully.

import sys
import re
import lib_util
import lib_common
from lib_properties import pc
import lib_smb

Usable = lib_smb.UsableNetCommands

def Main():
    cgiEnv = lib_common.CgiEnv()

    grph = cgiEnv.GetGraph()

    net_share_cmd = [ "net", "share" ]

    net_share_pipe = lib_common.SubProcPOpen(net_share_cmd)

    (net_share_last_output, net_share_err) = net_share_pipe.communicate()

    # Converts to string for Python3.
    as_str = net_share_last_output.decode("utf-8")
    #print("Str="+as_str)
    lines = as_str.split('\n')

    seen_hyphens = False

    for lin in lines:
        #print("se="+str(seen_hyphens)+" Lin=("+lin+")")
        if re.match(".*-------.*", lin):
            seen_hyphens = True
            continue

        if re.match(".*The command completed successfully.*", lin):
            break
        #print("se="+str(seen_hyphens)+" Lin1=("+lin+")")
        if not seen_hyphens:
            continue

        #print("se="+str(seen_hyphens)+" Lin2=("+lin+")")
        tst_share = re.match(r'^([A-Za-z0-9_$]+) +([^ ]+).*', lin)
        if not tst_share:
            continue

        shr_nam = tst_share.group(1)

        # Nasty formatting of "NET SHARE" command.
        if len(lin) >= 45:
            # There is a remark or a very long resource.
            if lin[44] == ' ':
                # Character just before remark is a space.
                shr_res = lin[13:44].rstrip()
            else:
                shr_res = lin[13:]
        else:
            shr_res = lin[13:]

        share_node = lib_common.gUriGen.SmbShareUri("//" + lib_util.currentHostname + "/" + shr_nam)
        grph.add((lib_common.nodeMachine, pc.property_smbshare, share_node))

        # mount_node = lib_common.gUriGen.FileUri( "//" + lib_util.currentHostname + "/" + shr_res )
        shr_res = shr_res.strip()
        shr_res = lib_util.standardized_file_path(shr_res)
        mount_node = lib_common.gUriGen.DirectoryUri(shr_res)
        grph.add((share_node, pc.property_smbmount, mount_node))

    cgiEnv.OutCgiRdf()

if __name__ == '__main__':
    Main()

