#!/usr/bin/python

"""
fuser command.

Identify processes using files or sockets with Linux command fuser
"""

import os
import sys

import lib_util
import lib_common
from lib_properties import pc

Usable = lib_util.UsableLinux

def Main():
	cgiEnv = lib_common.CgiEnv()
	fileName = cgiEnv.GetId()

	grph = cgiEnv.GetGraph()

	nodeFile = lib_common.gUriGen.FileUri( fileName )

	DEBUG("Fuser file=%s",fileName)

	lib_common.ErrorMessageHtml("linux_fuser.py not implemented yet")

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
