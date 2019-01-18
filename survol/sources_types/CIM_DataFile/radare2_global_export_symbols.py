#!/usr/bin/python

"""
List of global export symbols as detected by Radare2
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

	cmdR2 = ['radare2','-A','-q','-c','"iEj"', fileExeOrDll]
	DEBUG("cmdR2=%s\n"%str(cmdR2))

	r2Pipe = subprocess.Popen(cmdR2, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	r2Output, r2Err = r2Pipe.communicate()
	rc = r2Pipe.returncode

	DEBUG("r2Err=%s\n"%r2Err)
	DEBUG("rc=%s\n"%rc)
	DEBUG("r2Output=%s\n"%r2Output)


	#{
	#	"name":"SqlServerSpatial140.dll_?m_Points1@SampleDescriptor@@2QBNB",
	#	"demname":"",
	#	"flagname":"sym.SqlServerSpatial140.dll__m_Points1_SampleDescriptor__2QBNB",
	#	"ordinal":0,
	#	"bind":"GLOBAL",
	#	"size":0,
	#	"type":"FUNC",
	#	"vaddr":4691376,
	#	"paddr":490416},
	# ...

	fileWithExt = os.path.basename(fileExeOrDll)
	fileBasename, fileExtension = os.path.splitext(fileWithExt)

	iEjList = json.loads(r2Output)
	if iEjList:
		for iEjOne in iEjList:
			# "SqlServerSpatial140.dll_?m_Points1@SampleDescriptor@@2QBNB"
			iE_funcName = iEjOne["name"]
			iE_vaddr = iEjOne["vaddr"]
			iE_paddr = iEjOne["paddr"]

			symNod = lib_common.gUriGen.SymbolUri( iE_funcName, fileExeOrDll )

			grph.add( ( symNod, lib_common.MakeProp("vaddr"), lib_common.NodeLiteral(iE_vaddr) ) )
			grph.add( ( symNod, lib_common.MakeProp("paddr"), lib_common.NodeLiteral(iE_paddr) ) )
			grph.add( ( nodeExeOrDll, pc.property_symbol_defined, symNod ) )

	cgiEnv.OutCgiRdf("LAYOUT_RECT",[ pc.property_symbol_defined ] )

if __name__ == '__main__':
	Main()
