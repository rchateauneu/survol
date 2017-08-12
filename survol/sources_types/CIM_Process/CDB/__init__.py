"""
CDB Windows debugger
"""

import os
import sys
import lib_util

Usable = lib_util.UsableWindows

# It might be a Known DLL
# HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\KnownDLLs"
# All KnownDLLs are in the directory HKLM\System\CCS\Control\KnownDLLs\DllDirectory or
# HKLM\System\CCS\Control\KnownDLLs\DllDirectory32, respectively "%SystemRoot%\system32"
# or "%SystemRoot%\syswow64".
def TestIfKnownDll(filNam):
	sys.stderr.write("TestIfKnownDll filNam=%s\n"%filNam)
	if not filNam.upper().endswith(".DLL"):
		filNam += ".DLL"

	if not os.path.isfile(filNam):
		filNam32 = os.environ['SystemRoot'] + "\\system32\\" + filNam
		if os.path.isfile(filNam32):
			return filNam32

		filNam64 = os.environ['SystemRoot'] + "\\syswow64\\" + filNam
		if os.path.isfile(filNam64):
			return filNam64

	return filNam