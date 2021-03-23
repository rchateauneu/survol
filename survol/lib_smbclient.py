import re
import sys
import logging

import lib_uris
import lib_util
import lib_common
from lib_properties import pc


def SmbCleanupFilNam(fil_nam, filSz):
    smb_mtch = re.match("(.*[^ ]) +D +", fil_nam)
    if smb_mtch:
        return smb_mtch.group(1)

    smb_mtch = re.match( "(.*[^ ]) +A +", fil_nam)
    if smb_mtch:
        return smb_mtch.group(1)

    smb_mtch = re.match( "(.*[^ ]) +", fil_nam)
    if smb_mtch:
        return smb_mtch.group(1)

    # When the remote machine is Windows,
    # there are other codes such as DRH etc...

    # Very specific and instable formatting.
    # if filSz == "0" and filNam[-9:] == " D       ":
    #     filNam = filNam[:-10].rstrip()

    return fil_nam


def AddFromSmbClient(grph, smb_dir, smb_shr, pass_wrd, root_node):

    smbclient_cmd = ["smbclient", "-c", "ls", "-D", smb_dir, smb_shr, pass_wrd]

    # This print is temporary until we know how to display smb-shared files.
    logging.debug("Command=%s", str(smbclient_cmd))

    smbclient_pipe = lib_common.SubProcPOpen(smbclient_cmd)

    smbclient_last_output, smbclient_err = smbclient_pipe.communicate()

    lines = smbclient_last_output.split('\n')
    for lin in lines:
        logging.debug("l=" + lin)
        # Normally this is only the first line
        # session setup failed: NT_STATUS_LOGON_FAILURE
        mtch_net = re.match("^.*(NT_STATUS_.*)", lin)
        if mtch_net:
            lib_common.ErrorMessageHtml("Smb failure: " + mtch_net.group(1) + " shr:" + smb_shr + " dir:" + smb_dir)

        #   .                                   D        0  Wed Jul 23 23:22:34 2014
        #  ..                                  D        0  Sat Oct 19 00:25:58 2013
        #fldigi.exe                          A 40177610  Sat Jun 29 00:20:46 2013

        #  My Playlists                        D        0  Wed May  1 14:14:55 2013
        #  Sample Music                       DR        0  Wed May  1 19:46:06 2013

        reg_date = '[A-Za-z]+ +[A-Za-z]+ +[0-9]+ +[0-9]+:[0-9]+:[0-9]+ +[0-9]+'

        reg_full = '^(.*) ([0-9]+) +' + reg_date

        tst_fil = re.match(reg_full, lin)

        if tst_fil:
            fil_nam = tst_fil.group(1)[2:]
            fil_sz = tst_fil.group(2)

            fil_nam = SmbCleanupFilNam(fil_nam,fil_sz)

            logging.debug("Fi=%s, Sz=%s", fil_nam, fil_sz)

            fil_nod = lib_uris.gUriGen.SmbFileUri(smb_shr, smb_dir + "/" + fil_nam)
            grph.add((root_node, pc.property_directory, fil_nod))
