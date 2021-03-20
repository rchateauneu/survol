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
import logging
import lib_uris
import lib_util
import lib_common
import lib_properties
from lib_properties import pc
import lib_smb

# PS C:\Users\myself> Get-WmiObject -Query "select * from Win32_NetworkConnection"
#
# LocalName                     RemoteName                    ConnectionState               Status
# ---------                     ----------                    ---------------               ------
# Y:                            \\192.168.1.115\EmuleDownload Connected                     OK
# Z:                            \\192.168.1.61\Public         Connected                     OK
#                               \\mymachine\IPC$               Disconnected                  Degraded

# PS C:\Users\myself> net use
# New connections will be remembered.
#
#
# Status       Local     Remote                    Network
#
# -------------------------------------------------------------------------------
# OK           Y:        \\192.168.1.115\EmuleDownload
#                                                 Microsoft Windows Network
# OK           Z:        \\192.168.1.61\Public     Microsoft Windows Network
# OK                     \\mymachine\IPC$          Microsoft Windows Network

Usable = lib_util.UsableWindows


def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    grph = cgiEnv.GetGraph()

    net_use_cmd = ["net", "use"]

    net_use_pipe = lib_common.SubProcPOpen(net_use_cmd)

    net_use_last_output, net_use_err = net_use_pipe.communicate()

    # Converts to string for Python3.
    if lib_util.is_py3:
        asstr = net_use_last_output.decode("utf-8")
    else:
        asstr = net_use_last_output
    assert isinstance(asstr, str)
    lines = asstr.split('\n')

    seen_hyphens = False

    # When the remote field is too long, the content is split into two lines.

    for lin in lines:
        logging.debug("lin=%s", lin)
        assert isinstance(lin, str)
        if re.match(".*-------.*", lin):
            seen_hyphens = True
            continue

        if re.match(".*The command completed successfully.*",lin):
            break
        if not seen_hyphens:
            continue

        lin = lin.strip()
        if lin.startswith("Microsoft Windows Network"):
            # End of the previous line.
            continue

        lin_split = lin.split()
        if lin_split[0] not in ["OK", "Disconnected"]:
            lib_common.ErrorMessageHtml("Line is not ok:" + str(lin_split))

        if re.match("[A-Z]:", lin_split[1]):
            the_disk = lin_split[1][0].upper()
            the_path = lin_split[2]
        else:
            the_disk = ""
            the_path = lin_split[1]

        if not the_path.startswith("\\\\"):
            # "\\192.168.0.15\the_directory"
            lib_common.ErrorMessageHtml("Invalid path:" + the_path)

        the_path_split = the_path.split("\\")
        try:
            share_host = the_path_split[2]
            share_name = the_path_split[3]
        except IndexError:
            lib_common.ErrorMessageHtml("Cannot parse the_path=%s", the_path)

        # "\\192.168.0.15\the_directory   Microsoft Windows Network"

        # This is a normal share but on a remote machine.
        share_box = lib_uris.MachineBox(share_host)
        remote_share_node = share_box.SmbShareUri(share_host)

        remote_server_node = lib_uris.gUriGen.HostnameUri(share_host)

        # Win32_NetworkConnection: The key is the disk name.
        connected_disk_node = lib_uris.gUriGen.Win32_NetworkConnectionUri(the_disk)
        connected_file_node = lib_uris.gUriGen.FileUri(the_disk)
        logging.debug("share_name=%s", share_name)
        logging.debug("share_box=%s", share_box)
        grph.add((connected_disk_node, pc.property_mount, remote_share_node))
        grph.add((remote_server_node, pc.property_smbshare, remote_share_node))


    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
