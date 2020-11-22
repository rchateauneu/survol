#!/usr/bin/env python

"""
Windows network devices
Command wmic logicaldisk
"""

import re
import sys
import lib_util
import lib_common
from lib_properties import pc


def Main():
    cgiEnv = lib_common.CgiEnv()

    grph = cgiEnv.GetGraph()

    #on windows
    #Get the fixed drives
    #wmic logicaldisk get name,description
    # We could also use the WMI package index but the point here
    # is also to prove that as long as we return RDF data, the
    # implementation details have no importance.

    # What about the ftp disks

    # Nothing is done for Linux because this is a different logic,
    # so there is no point emulating the same behaviour.

    drivelist = lib_common.SubProcPOpen('wmic logicaldisk get name,description,ProviderName')
    drivelisto, err = drivelist.communicate()
    strlist = drivelisto
    # This was the original line tested on Python 3 on Windows, but on Linux we get:
    # drive_lines = strlist.split(b'\n') SyntaxError: invalid syntax
    # So we have replaced it, but this must be tested.
    # On Windows, now we get "Type str doesn't support the buffer API"
    # drive_lines = strlist.split('\n')

    if lib_util.is_py3:
        strlist_str = str(strlist, encoding='utf8')
    else:
        strlist_str = str(strlist )
    drive_lines = strlist_str.split('\n')

    dict_hosts = {}

    for lin in drive_lines[1:]:
        devtype = lin[0:18].strip()
        devname = lin[20:21]
        devprov = lin[22:].strip()
        # End of the list not interesting.
        if devtype == "":
            break
        if devtype != "Network Connection":
            continue

        # TODO: Put this in lib_common
        dev_split = devprov.split('\\')
        host_name = dev_split[2]

        try:
            host_node = dict_hosts[host_name]
        except KeyError:
            host_node = lib_common.gUriGen.HostnameUri(host_name)
            dict_hosts[host_name] = host_node

        disk_node = lib_common.gUriGen.SmbShareUri("//" + host_name + "/" + dev_split[3])

        # grph.add( ( disk_node, pc.property_win_netdev, lib_util.NodeLiteral( devname ) ) )

        grph.add((lib_common.gUriGen.FileUri(devname + ':'), pc.property_mount, disk_node))

        grph.add((disk_node, pc.property_file_system_type, lib_util.NodeLiteral( devtype)))

        grph.add((host_node, pc.property_smbshare, disk_node))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
