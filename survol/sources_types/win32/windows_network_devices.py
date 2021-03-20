#!/usr/bin/env python

"""
Windows network devices

Command wmic logicaldisk
"""

import re
import sys
import logging
import lib_uris
import lib_util
import lib_common
from lib_properties import pc


def Main():
    cgiEnv = lib_common.CgiEnv()

    grph = cgiEnv.GetGraph()

    # C:\Users\the_user>wmic logicaldisk get name,description,ProviderName
    # Description         Name  ProviderName
    # Local Fixed Disk    C:
    # Local Fixed Disk    D:
    # Local Fixed Disk    E:
    # CD-ROM Disc         F:
    # Network Connection  Y:    \\192.168.1.115\EmuleDownload
    # Network Connection  Z:    \\192.168.1.61\Public

    drivelist = lib_common.SubProcPOpen('wmic logicaldisk get name,description,ProviderName')
    drivelisto, err = drivelist.communicate()
    strlist = drivelisto

    if lib_util.is_py3:
        strlist_str = str(strlist, encoding='utf8')
    else:
        strlist_str = str(strlist)
    drive_lines = strlist_str.split('\n')

    for lin in drive_lines[1:]:
        devtype = lin[0:18].strip()
        devname = lin[20:21]
        devprov = lin[22:].strip()
        # End of the list not interesting.
        if devtype == "":
            break
        if devtype != "Network Connection":
            continue

        dev_split = devprov.split('\\')
        host_name = dev_split[2]
        share_name = dev_split[3]

        share_box = lib_uris.MachineBox(host_name)
        remote_share_node = share_box.SmbShareUri(share_name)

        host_node = lib_uris.gUriGen.HostnameUri(host_name)

        # See net_use.py which creates the same type of output. Win32_NetworkConnection key is the disk name.
        connected_disk_node = lib_uris.gUriGen.Win32_NetworkConnectionUri(devname)
        connected_file_node = lib_uris.gUriGen.FileUri(devname)
        logging.debug("share_name=%s", share_name)
        logging.debug("share_box=%s", share_box)
        grph.add((connected_disk_node, pc.property_mount, remote_share_node))
        grph.add((host_node, pc.property_smbshare, remote_share_node))


        #host_node = lib_common.gUriGen.HostnameUri(host_name)
        #disk_node = lib_uris.gUriGen.SmbShareUri(share_name)
        #grph.add((lib_common.gUriGen.FileUri(devname + ':'), pc.property_mount, disk_node))
        #grph.add((disk_node, pc.property_file_system_type, lib_util.NodeLiteral(devtype)))
        #grph.add((host_node, pc.property_smbshare, disk_node))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
