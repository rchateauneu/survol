#!/usr/bin/python

"""
List of functions extracted by Radare2
"""

import os
import sys
import json
import lib_util
import lib_common
from lib_properties import pc
import subprocess

Usable = lib_util.UsableWindowsBinary or lib_util.UsableLinuxBinary

def Main():
	cgiEnv = lib_common.CgiEnv()

	fileExeOrDll = cgiEnv.GetId()

	grph = cgiEnv.GetGraph()

	nodeExeOrDll = lib_common.gUriGen.FileUri( fileExeOrDll )

	cmdR2 = ['radare2','-A','-q','-c','"aflj"', fileExeOrDll]
	DEBUG("cmdR2=%s\n"%str(cmdR2))

	r2Pipe = subprocess.Popen(cmdR2, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	r2Output, r2Err = r2Pipe.communicate()
	rc = r2Pipe.returncode

	DEBUG("r2Err=%s\n"%r2Err)
	DEBUG("rc=%s\n"%rc)
	DEBUG("r2Output=%s\n"%r2Output)

	# {
	# 	"offset":6442455744,
	# 	"name":"sub.KERNEL32.dll_AcquireSRWLockShared_2c0",
	# 	"size":305,
	# 	"is-pure":false,
	# 	"realsz":305,
	# 	"stackframe":56,
	# 	"calltype":"amd64",
	# 	"cost":137,
	# 	"cc":7,
	# 	"bits":64,
	# 	"type":"fcn",
	# 	"nbbs":14,
	# 	"edges":19,
	# 	"ebbs":1,
	# 	"minbound":"-2147478848",
	# 	"maxbound":"-2147478543",
	# 	"callrefs":[
	# 		{"addr":6442455889,"type":"J","at":6442455801},
	# 		{"addr":6442479744,"type":"C","at":6442455810},
	# 		...
	# 		{"addr":6442456025,"type":"J","at":6442456018}],
	# 	"datarefs":[6442504200,6442504200,6442504200,6442504200,6442504200],
	# 	"codexrefs":[{"addr":6442462443,"type":"C","at":6442455744},
	# 				 ...
	# 				 {"addr":6442455907,"type":"J","at":6442456030}],
	# 	"dataxrefs":[],
	# 	"indegree":12,
	# 	"outdegree":8,
	# 	"nlocals":0,
	# 	"nargs":11,
	# 	"bpvars":[],
	# 	"spvars":[{"name":"arg_8h","kind":"arg","type":"int","ref":{"base":"rsp", "offset":47244640264}},
	# 			  ...
	# 			  {"name":"arg_60h","kind":"arg","type":"int","ref":{"base":"rsp", "offset":47244640352}}],
	# 	"regvars":[{"name":"arg6","kind":"reg","type":"int","ref":"r9"},
	# 			   ...
	# 			   {"name":"arg4","kind":"reg","type":"int","ref":"rcx"}],
	# 	"difftype":"new"},
	# ...

	fileWithExt = os.path.basename(fileExeOrDll)
	fileBasename, fileExtension = os.path.splitext(fileWithExt)

	def DllBaseNameToPath(dllBaseName):
		if dllBaseName.upper() == fileBasename.upper():
			return fileExeOrDll
		else:
			# Otherwise we have to find the library.
			dllName = dllBaseName + ".dll"
			# TODO: This is not the correct directory
			return "c:/windows/system32/"+dllName


	afljList = json.loads(r2Output)
	if afljList:
		for afljOne in afljList:
			funcName = afljOne["name"]

			if funcName.startswith("sym.imp."):
				# sym.ADVAPI32.dll_AuditComputeEffectivePolicyBySid
				# sym.imp.KERNEL32.dll_WriteFile
				# sym.imp.RPCRT4.dll_RpcBindingFree
				# sym.imp.msvcrt.dll_wcschr
				# sym.imp.ntdll.dll_NtClose
				funcNameSplit = funcName.split(".")
				dllBaseName = funcNameSplit[2]
				rawEntryName = funcNameSplit[3]
				if not rawEntryName.startswith("dll_"):
					# Unexpected symbol name.
					continue
				rawEntryName = rawEntryName[4:]

				dllPathName = DllBaseNameToPath(dllBaseName)

				# If this is a local function. Uppercases for Windows only.
				symNod = lib_common.gUriGen.SymbolUri( rawEntryName, dllPathName )

			elif funcName.startswith("sub."):
				# sub.CRYPTSP.dll_CryptCreateHash_6_e71	Call_type	cdecl
				# sub.CRYPTSP.dll_CryptCreateHash_edb


				# anal.autoname=true/false ??

				funcNameSplit = funcName.split(".")

				# This could be "sub.0123456789abcdef_efc"
				if len(funcNameSplit) != 3:
					continue

				dllBaseName = funcNameSplit[1]
				rawEntryNameWithOffset = funcNameSplit[2]
				rawEntryName = rawEntryNameWithOffset
				if not rawEntryName.startswith("dll_"):
					# Unexpected symbol name.
					continue
				rawEntryName = rawEntryName[4:]

				dllPathName = DllBaseNameToPath(dllBaseName)

				# If this is a local function. Uppercases for Windows only.
				symNod = lib_common.gUriGen.SymbolUri( rawEntryName, dllPathName )
			elif funcName.startswith("fcn."):
				# fcn.77c63e7e	Call_type	cdecl
				# fcn.77c63ed4	Call_type	cdecl
				# fcn.77c63eed	Call_type	cdecl
				symNod = lib_common.gUriGen.SymbolUri( funcName, fileExeOrDll )
			else:
				continue

			grph.add( ( symNod, lib_common.MakeProp("Call type"), lib_common.NodeLiteral(afljOne["calltype"]) ) )
			grph.add( ( nodeExeOrDll, pc.property_symbol_defined, symNod ) )

	cgiEnv.OutCgiRdf("LAYOUT_RECT",[ pc.property_symbol_defined ] )

if __name__ == '__main__':
	Main()
