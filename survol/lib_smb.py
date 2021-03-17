import re
import lib_common
import lib_uris


def UsableNetCommands(entity_type, entity_ids_arr):
    """NET command must be available. This can be the case on Linux."""
    return True


def SmbBothUriSplit(smb_both):
    """This receives a SMB share and returns its node, plus the share and the directory."""
    shr_mtch = re.match("//([^/]+)/([^/]+)/(.*)", smb_both)

    if not shr_mtch:
        return None

    smb_host = shr_mtch.group(1)
    smb_shr = shr_mtch.group(2)
    smb_dir = shr_mtch.group(3)
    smb_box = lib_uris.MachineBox(smb_host)
    # Needed if this is the top directory.
    if smb_dir == "" or smb_dir == "/":
        node_smb = smb_box.SmbShareUri(smb_shr)
    else:
        # Otherwise it is the directory of the current file.
        node_smb = smb_box.SmbFileUri(smb_shr, smb_dir)
    return node_smb, smb_shr, smb_dir

