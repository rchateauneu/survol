#!/usr/bin/python

"""
Import symbols detected by Radare2
"""

import os
import sys
import json
import lib_util
import lib_common
from lib_properties import pc
import subprocess

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

		for iEjOne in iijList:
			# "SqlServerSpatial140.dll_?m_Points1@SampleDescriptor@@2QBNB"
			iE_funcNameRaw = iEjOne["name"]
			ieOtherShortDllName, _, iE_funcName = iE_funcNameRaw.partition(".")
			iE_plt = iEjOne["plt"]
			iE_type = iEjOne["type"]
			iE_bind = iEjOne["bind"]

			ieOtherDllName = ieOtherShortDllName

			try:
				nodeExeOrDll = dictDllToNode[ieOtherDllName]
			except KeyError:
				nodeExeOrDll = lib_common.gUriGen.FileUri( ieOtherDllName )
				dictDllToNode[ieOtherDllName] = nodeExeOrDll

			symNod = lib_common.gUriGen.SymbolUri( iE_funcName, ieOtherDllName )

			grph.add( ( symNod, lib_common.MakeProp("plt"), lib_common.NodeLiteral(iE_plt) ) )
			grph.add( ( symNod, lib_common.MakeProp("type"), lib_common.NodeLiteral(iE_type) ) )
			grph.add( ( symNod, lib_common.MakeProp("bind"), lib_common.NodeLiteral(iE_bind) ) )
			grph.add( ( nodeExeOrDll, pc.property_symbol_defined, symNod ) )

	cgiEnv.OutCgiRdf("LAYOUT_RECT",[ pc.property_symbol_defined ] )

if __name__ == '__main__':
	Main()
