#!/usr/bin/python

"""
Import symbols detected by Radare2
"""

import json
import subprocess
import lib_common
import lib_shared_lib_path
from lib_properties import pc

def Main():
	cgiEnv = lib_common.CgiEnv()

	fileExeOrDll = cgiEnv.GetId()

	grph = cgiEnv.GetGraph()

	nodeExeOrDll = lib_common.gUriGen.FileUri( fileExeOrDll )

	cmdR2 = ['radare2','-A','-q','-c','"iij"', fileExeOrDll]
	DEBUG("cmdR2=%s\n"%str(cmdR2))

	r2Pipe = subprocess.Popen(cmdR2, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	r2Output, r2Err = r2Pipe.communicate()
	rc = r2Pipe.returncode

	DEBUG("r2Err=%s\n"%r2Err)
	DEBUG("rc=%s\n"%rc)
	DEBUG("r2Output=%s\n"%r2Output)


	#
	# {
	# "ordinal":1,
	# "bind":"NONE",
	# "type":"FUNC",
	# "name":"MSVCR120.dll__isnan",
	# "plt":4689968
	# },
	# ...

	iijList = json.loads(r2Output)
	if iijList:
		dictDllToNode = {}

		for iijOne in iijList:
			# "SqlServerSpatial140.dll_?m_Points1@SampleDescriptor@@2QBNB"
			ii_funcNameRaw = iijOne["name"]
			ii_OtherShortDllName, _, ii_funcName = ii_funcNameRaw.partition(".")
			if ii_funcName.startswith("dll_"):
				ii_funcName = ii_funcName[4:]
			ii_plt = iijOne["plt"]
			ii_type = iijOne["type"]
			ii_bind = iijOne["bind"]


			try:
				nodeExeOrDll = dictDllToNode[ii_OtherShortDllName]
			except KeyError:
				ii_OtherDllName = ii_OtherShortDllName + ".dll"
				ieOtherDllPath = lib_shared_lib_path.FindPathFromSharedLibraryName(ii_OtherDllName)
				if ieOtherDllPath is None:
					WARNING("Cannot find library for ii_OtherShortDllName=%s",ii_OtherDllName)
					ieOtherDllPath = ii_OtherDllName
				nodeExeOrDll = lib_common.gUriGen.FileUri( ieOtherDllPath )
				dictDllToNode[ii_OtherShortDllName] = nodeExeOrDll

			symNod = lib_common.gUriGen.SymbolUri( ii_funcName, ieOtherDllPath )

			grph.add( ( symNod, lib_common.MakeProp("plt"), lib_common.NodeLiteral(ii_plt) ) )
			grph.add( ( symNod, lib_common.MakeProp("type"), lib_common.NodeLiteral(ii_type) ) )
			grph.add( ( symNod, lib_common.MakeProp("bind"), lib_common.NodeLiteral(ii_bind) ) )
			grph.add( ( nodeExeOrDll, pc.property_symbol_defined, symNod ) )

	cgiEnv.OutCgiRdf("LAYOUT_RECT",[ pc.property_symbol_defined ] )

if __name__ == '__main__':
	Main()
