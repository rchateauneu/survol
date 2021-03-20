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


def AddDepends(grph, node_shared_lib, library):
	lib_node = lib_common.gUriGen.SharedLibUri(library)
	grph.add((node_shared_lib, pc.property_library_depends, lib_node))
	# This assumes that shared libraries are a special sort of file.
	# This is true, but not completely used.
	CIM_DataFile.AddInfo(grph, lib_node, [library])


def Main():
	cgiEnv = lib_common.ScriptEnvironment()
	file_shared_lib = cgiEnv.GetId()

	if not lib_util.isPlatformLinux:
		lib_common.ErrorMessageHtml("LDD on Linux platform only")

	grph = cgiEnv.GetGraph()

	# Maybe the file does not contain its path so it must be added.
	if file_shared_lib[0] != '/':
		file_shared_lib = os.getcwd() + '/' + file_shared_lib

	node_shared_lib = lib_common.gUriGen.SharedLibUri(file_shared_lib)
	CIM_DataFile.AddInfo( grph, node_shared_lib, [file_shared_lib])

	stream = os.popen("ldd " + file_shared_lib)

	# Line read are such as:
	#        linux-gate.so.1 =>  (0xffffe000)
	#        libdl.so.2 => /lib/libdl.so.2 (0xb7dae000)
	#        libc.so.6 => /lib/i686/libc.so.6 (0xb7c6a000)
	#        /lib/ld-linux.so.2 (0x80000000)
	# Do not know what to do with the lines without an arrow.
	# Do not know what happens if a library name contains a space.
	rgx = re.compile(r'^.*=> *([^ ]+) \(')

	for line in stream:
		match_obj = re.match(rgx, line)
		if match_obj:
			AddDepends(grph, node_shared_lib, match_obj.group(1))

	# The dependencies are flattened which may be is a mistake.
	cgiEnv.OutCgiRdf("LAYOUT_RECT")


if __name__ == '__main__':
	Main()

