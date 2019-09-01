#!/usr/bin/env python

"""
Shared library dependencies (Linux)
"""

import os
import re
import sys
import socket
import urllib
import lib_util
from sources_types import CIM_DataFile
import lib_common
from lib_properties import pc

Usable = lib_util.UsableLinuxBinary

def DoNothing():
	return

def AddDepends(grph, nodeSharedLib, library):
	libNode = lib_common.gUriGen.SharedLibUri( library )
	grph.add( ( nodeSharedLib, pc.property_library_depends, libNode ) )
	# This assumes that shared libraries are a special sort of file.
	# This is true, but not completely used.
	CIM_DataFile.AddInfo( grph, libNode, [ library ] )

def Main():
	cgiEnv = lib_common.CgiEnv()
	fileSharedLib = cgiEnv.GetId()

	if not lib_util.isPlatformLinux:
		lib_common.ErrorMessageHtml("LDD on Linux platform only")

	grph = cgiEnv.GetGraph()

	# Maybe the file does not contain its path so it must be added.
	if ( fileSharedLib[0] != '/' ):
		fileSharedLib = os.getcwd() + '/' + fileSharedLib

	nodeSharedLib = lib_common.gUriGen.SharedLibUri( fileSharedLib )
	CIM_DataFile.AddInfo( grph, nodeSharedLib, [ fileSharedLib ] )

	stream = os.popen("ldd " + fileSharedLib)

	# Line read are such as:
	#        linux-gate.so.1 =>  (0xffffe000)
	#        libdl.so.2 => /lib/libdl.so.2 (0xb7dae000)
	#        libc.so.6 => /lib/i686/libc.so.6 (0xb7c6a000)
	#        /lib/ld-linux.so.2 (0x80000000)
	# Do not know what to do with the lines without an arrow.
	# Do not know what happens if a library name contains a space.
	rgx = re.compile('^.*=> *([^ ]+) \(')

	for line in stream:
		matchObj = re.match( rgx, line )
		if matchObj:
			AddDepends( grph, nodeSharedLib, matchObj.group(1) )

	# The dependencies are flattened which may be is a mistake.

	cgiEnv.OutCgiRdf("LAYOUT_RECT")

if __name__ == '__main__':
	Main()

