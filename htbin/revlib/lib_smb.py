import re
import lib_common

def SmbBothUriSplit(smbBoth):
    shr_mtch = re.match( "//([^/]+)/([^/]+)/(.*)", smbBoth )

    if not shr_mtch:
        return None

    smbShr = "//" + shr_mtch.group(1) + "/" + shr_mtch.group(2)
    smbDir = shr_mtch.group(3)

    # Needed if this is the top directory.
    if smbDir == "" or smbDir == "/" :
        nodeSmb = lib_common.gUriGen.SmbShareUri( smbShr )
    else:
        # Otherwise it is the directory of the current file.
        nodeSmb = lib_common.gUriGen.SmbFileUri( smbShr, smbDir )
    return nodeSmb,smbShr,smbDir

