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
# MySelf         C:\Documents and Settings\MySelf
# SharedDocs   C:\DOCUMENTS AND SETTINGS\ALL USERS\DOCUMENTS
#
# The command completed successfully.


# PS C:\Users\myself> Get-WmiObject -Query "select * from Win32_Share"
#
# Name                                    Path                                    Description
# ----                                    ----                                    -----------
# ADMIN$                                  C:\windows                              Remote Admin
# C$                                      C:\                                     Default share
# D$                                      D:\                                     Default share
# E$                                      E:\                                     Default share
# IPC$                                                                            Remote IPC
# SharedProviderTutorial                  C:\Users\rchateau\Developpement\Reve...
# ShrProvTuto                             C:\Users\rchateau\Developpement\Reve...
# Users                                   C:\Users

import sys
import re
import lib_util
import lib_common
import lib_uris
from lib_properties import pc
import lib_smb

Usable = lib_util.UsableWindows


def Main():
    cgiEnv = lib_common.CgiEnv()

    grph = cgiEnv.GetGraph()

    net_share_cmd = ["net", "share"]

    net_share_pipe = lib_common.SubProcPOpen(net_share_cmd)

    net_share_last_output, net_share_err = net_share_pipe.communicate()

    # Converts to string for Python3.
    as_str = net_share_last_output.decode("utf-8")

    lines = as_str.split('\n')

    seen_hyphens = False

    for lin in lines:
        if re.match(".*-------.*", lin):
            seen_hyphens = True
            continue

        if re.match(".*The command completed successfully.*", lin):
            break
        if not seen_hyphens:
            continue

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

        share_node = lib_uris.gUriGen.SmbShareUri(shr_nam)
        grph.add((lib_common.nodeMachine, pc.property_smbshare, share_node))

        # mount_node = lib_common.gUriGen.FileUri( "//" + lib_util.currentHostname + "/" + shr_res )
        shr_res = shr_res.strip()
        shr_res = lib_util.standardized_file_path(shr_res)
        mount_node = lib_common.gUriGen.DirectoryUri(shr_res)
        grph.add((share_node, pc.property_smbmount, mount_node))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()

