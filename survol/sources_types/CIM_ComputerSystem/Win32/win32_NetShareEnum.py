#!/usr/bin/env python

"""
Network shares
"""

import sys
import logging
import lib_util
import lib_common
import lib_uris
from lib_properties import pc

import win32net


def Main():
    cgiEnv = lib_common.ScriptEnvironment()
    hostname = cgiEnv.GetId()

    nodeHost = lib_uris.gUriGen.HostnameUri(hostname)

    grph = cgiEnv.GetGraph()

    # Loop over the shares.
    shareresume=0
    while 1:
        try:
            # If running on the local machine, pass the host as None otherwise authorization is checked
            # just like a remote machine, which means User Account Control (UAC) disabling,
            # and maybe setting LocalAccountTokenFilterPolicy=1
            if lib_util.is_local_address( hostname ):
                hostname_or_None = None
                level = 2 # 1,2
            else:
                hostname_or_None = hostname
                level = 1 # 1,2

            sharedata, total, shareresume = win32net.NetShareEnum(hostname_or_None, level, shareresume)

        except Exception as exc:
            # "Access is denied."
            lib_common.ErrorMessageHtml("Hostname=" + hostname + ". Exception:" + str(exc))

        for share in sharedata:
            logging.debug("share=%s", str(share))
            # share={'remark': 'Remote Admin', 'passwd': None, 'current_uses': 0, 'netname': 'ADMIN$', 'max_uses': 4294967295, 'path': 'C:\\\\Windows', 'type': 2147483648, 'permissions': 0}
            share_netname = share['netname']
            try:
                share_path = share['path']
                share_remark = share['remark']
            except:
                share_path = ""
                share_remark = ""

            shareNode = lib_uris.MachineBox(hostname).SmbShareUri(share_netname)
            grph.add((nodeHost, pc.property_smbshare, shareNode))

            if share_path:
                mountNode = lib_uris.gUriGen.FileUri(share_path)
                grph.add((shareNode, pc.property_smbmount, mountNode))

            if share_remark:
                grph.add((shareNode, pc.property_information, lib_util.NodeLiteral(share_remark)))

        if not shareresume:
            break

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
