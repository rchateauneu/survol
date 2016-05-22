#!/usr/bin/python

"""
Windows process modules
"""

import os
import sys
import rdflib
import lib_util
import lib_common
import lib_entities.lib_entity_CIM_Process
from lib_properties import pc

Usable = lib_util.UsableWindows

from ctypes import *

psapi = windll.psapi
kernel = windll.kernel32


def Main():
	cgiEnv = lib_common.CgiEnv()
	pid = int( cgiEnv.GetId() )

	# TODO: These are probably in win32com or a similar module.
	PROCESS_QUERY_INFORMATION = 0x0400
	PROCESS_VM_READ = 0x0010

	grph = rdflib.Graph()

	node_process = lib_common.gUriGen.PidUri(pid)
	exec_node = lib_entities.lib_entity_CIM_Process.AddInfo( grph, node_process, [ pid ] )

	#Get handle to the process based on PID
	hProcess = kernel.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
	if hProcess:
		ModuType = c_ulong * 512
		hModuleArr = ModuType()
		rawCntModules = c_ulong()
		psapi.EnumProcessModules(hProcess, byref(hModuleArr), sizeof(hModuleArr), byref(rawCntModules))
		nbModules = int( rawCntModules.value/sizeof(c_ulong()) )
		if nbModules >= 512:
			raise Exception("Disaster overrun")

		modname = c_buffer(256)
		for idx in range( 0, nbModules ):
			retLen = psapi.GetModuleFileNameExA(hProcess, hModuleArr[idx], modname, sizeof(modname))
			tab = modname[:retLen]
			if sys.version_info >= (3,):
				# Truncation because "b'C:/xxx/yyy.zzz'", on Python 3
				filnam = str(tab).replace('\\','/')[2:-1]
			else:
				filnam = tab

			if idx > 0:
				libNode = lib_common.gUriGen.SharedLibUri( filnam )
				grph.add( ( exec_node, pc.property_library_depends, libNode ) )

		kernel.CloseHandle(hProcess)

	# Quelque chose deconne la dedans car ca reste bloque alors meme
	# que le svg est correct. Meme resultat avec IE.
	# Pour un svg qui n est pas tres grand, et dont le contenu est correct.
	# http://127.0.0.1/Survol/htbin/sources_types/Win32_Service/service_dependencies.py?xid=Win32_Service.Name%3Dnsi


	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()
