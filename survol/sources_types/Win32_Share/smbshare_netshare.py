#!/usr/bin/env python

"""
NET SHARE information
"""

# Output example:
#> net share C$
#Share name        C$
#Path              C:\
#Remark            Default share
#Maximum users     No limit
#Users
#Caching           Manual caching of documents
#Permission        Everyone, FULL
#
#The command completed successfully.

import re
import sys
import rdflib
import lib_util
import lib_common
from lib_properties import pc
import lib_uris


def Main():
    cgiEnv = lib_common.ScriptEnvironment()
    # Ex: "//LONW00052257.euro.net.intra/D$"
    smb_shr = cgiEnv.GetId()

    if not lib_util.isPlatformWindows:
        lib_common.ErrorMessageHtml("NET command on Windows only")

    # If called fron cgiserver.py, double slashes are collapsed into one.
    shr_match = re.match( "/?/([^/]+)/([^/]+)", smb_shr)
    if not shr_match:
        # It can also tolerate backslahes.
        smb_shr = smb_shr.replace("\\", "/")
        shr_match = re.match("/?/([^/]+)/([^/]+)", smb_shr)
        if not shr_match:
            # It also accepts backslashes instead of slashes.
            lib_common.ErrorMessageHtml("Invalid share name:%s" % smb_shr)

    host_name = shr_match.group(1)
    host_node = lib_uris.gUriGen.HostnameUri(host_name)

    shr_nam = shr_match.group(2)

    node_smb_shr = lib_uris.gUriGen.SmbShareUri(smb_shr)

    grph = cgiEnv.GetGraph()

    # TODO: This can work only on the local machine.
    net_share_cmd = ["net", "share", shr_nam]

    net_share_pipe = lib_common.SubProcPOpen(net_share_cmd)

    net_share_last_output, net_share_err = net_share_pipe.communicate()

    # Converts to string for Python3.
    asstr = net_share_last_output.decode("utf-8")

    # Share name        ShrProvTuto
    # Path              C:\Users\jsmith\Developpement\ReverseEngineeringApps\SharedProviderTutorial
    # Remark
    # Maximum users     No limit

    lines = asstr.split('\n')

    prop_map = dict()
    shr_path = None
    for lin in lines:
        txt_content = lin[18:].strip()
        if lin.startswith("Path"):
            shr_path = txt_content
        else:
            prop_key = lin[:18].strip()
            if prop_key:
                prop_map[prop_key] = txt_content

    for prop_key in prop_map:
        prop_val = prop_map[prop_key]
        grph.add((node_smb_shr, lib_common.MakeProp(prop_key), rdflib.Literal(prop_val)))

    if shr_path:
        mount_node = lib_uris.MachineBox(lib_util.currentHostname).FileUri(shr_path)
        grph.add((node_smb_shr, pc.property_smbmount, mount_node))

    grph.add((node_smb_shr, pc.property_host, host_node))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
