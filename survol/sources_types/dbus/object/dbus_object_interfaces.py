#!/usr/bin/env python

"""
DBus object interfaces
"""

import os
import sys
import dbus
import lib_common
import lib_util
import lib_dbus
from lib_properties import pc

Usable = lib_util.UsableLinux

def Main():
	cgiEnv = lib_common.CgiEnv()
	connectionName = cgiEnv.GetId()

	grph = cgiEnv.GetGraph()

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
