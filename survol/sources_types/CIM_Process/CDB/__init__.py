"""
CDB Windows debugger
"""

import os
import sys
import lib_util

Usable = lib_util.UsableWindows


def TestIfKnownDll(fil_nam):
    """
    It might be a Known DLL
    HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\KnownDLLs"
    All KnownDLLs are in the directory HKLM\System\CCS\Control\KnownDLLs\DllDirectory or
    HKLM\System\CCS\Control\KnownDLLs\DllDirectory32, respectively "%SystemRoot%\system32" or "%SystemRoot%\syswow64".
    """
    DEBUG("TestIfKnownDll filNam=%s", fil_nam)
    if not fil_nam.upper().endswith(".DLL"):
        fil_nam += ".DLL"

    if not os.path.isfile(fil_nam):
        filNam32 = os.environ['SystemRoot'] + "\\system32\\" + fil_nam
        if os.path.isfile(filNam32):
            return filNam32

        filNam64 = os.environ['SystemRoot'] + "\\syswow64\\" + fil_nam
        if os.path.isfile(filNam64):
            return filNam64

    return fil_nam