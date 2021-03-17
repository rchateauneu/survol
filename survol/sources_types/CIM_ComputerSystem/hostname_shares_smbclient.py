#!/usr/bin/env python

"""
Samba shares
"""

#$ smbclient -L DUOLNX -N
#Anonymous login successful
#Domain=[MDKGROUP] OS=[Unix] Server=[Samba 3.0.28a]
#
#        Sharename       Type      Comment
#        ---------       ----      -------
#        print$          Disk
#        pdf-gen         Printer   PDF Generator (only valid users)
#        homes           Disk      Home Directories
#        IncomingCopied  Disk      IncomingCopied
#        IncomingToCopy  Disk      IncomingToCopy
#        Samsung         Disk      SamsungDisk
#        IPC$            IPC       IPC Service (Samba Server 3.0.28a DuoLinux)
#Anonymous login successful
#Domain=[MDKGROUP] OS=[Unix] Server=[Samba 3.0.28a]
#
#        Server               Comment
#        ---------            -------
#        DUOLNX               Samba Server 3.0.28a DuoLinux
#
#        Workgroup            Master
#        ---------            -------
#        HOME                 BTHUB5
#        MDKGROUP             DUOLNX


import re
import os
import sys
import cgi        # One of the CGI arguments is the name of the Samba server
import lib_util
import lib_common
from lib_properties import pc


def Main():
    """
    This is similar to the script displaying shares for a given SMB server.
    Maybe in the future it will have to be different.
    """
    cgiEnv = lib_common.CgiEnv()
    host_name = cgiEnv.GetId()

    grph = cgiEnv.GetGraph()

    node_smb_shr = lib_common.gUriGen.SmbServerUri(host_name)

    smbclient_cmd = ["smbclient", "-L", host_name, "-N"]

    try:
        smbclient_pipe = lib_common.SubProcPOpen(smbclient_cmd)
    except Exception:
        lib_common.ErrorMessageHtml("Cannot run command:" + " ".join(smbclient_cmd))

    smbclient_last_output, smbclient_err = smbclient_pipe.communicate()

    lines = smbclient_last_output.split('\n')

    mode_shared_list = False
    for lin in lines:
        # print( "l="+lin+"<br>" )
        # Normally this is only the first line
        # session setup failed: NT_STATUS_LOGON_FAILURE
        mtch_net = re.match(r"^.*(NT_STATUS_.*)", lin)
        if mtch_net:
            # print("OK<br>")
            lib_common.ErrorMessageHtml("Smb failure: " + mtch_net.group(1) + " to smb share:" + node_smb_shr)

        if re.match(r"^\sServer\s+Comment", lin):
            mode_shared_list = False
            continue

        if re.match(r"^\sWorkgroup\s+Master", lin):
            mode_shared_list = False
            continue

        if re.match(r"^\sSharename\s+Type\s+Comment", lin):
            mode_shared_list = True
            continue

        if re.match (r"^\s*----+ +---+ +", lin):
            continue

        # print("m="+str(mode_shared_list))
        # print("l="+lin)
        if mode_shared_list:
            # The type can be "Disk", "Printer" or "IPC".
            mtch_share = re.match(r"^\s+([^\s]+)\s+Disk\s+(.*)$", lin)
            if mtch_share:
                share_name = mtch_share.group(1)

                share_node = lib_common.MachineBox(host_name).SmbShareUri(share_name)

                grph.add((node_smb_shr, pc.property_smbshare, share_node))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()

